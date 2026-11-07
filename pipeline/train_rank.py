"""Train the exploitation ranking ensemble, backtest it on a 2025 mirror of the benchmark,
and write top500.csv / epss_history.csv.

Leakage rules (see docs/columns_used.md):
  * every feature is what was known at the end of the row's snapshot month
  * never used: nvd_status, n_references, n_affected_cpes, cvss3_source, references.csv,
    affected_products.csv, and blank-vs-filled CVSS (missing scores are imputed, no indicator)
  * KEV dates are used only for labels and for "as of" counts that stop before the snapshot

Run:  python -m pipeline.train_rank            (backtest + final top500)
"""
from __future__ import annotations

import json
import re

import lightgbm as lgb
import numpy as np
import pandas as pd
import xgboost as xgb
from scipy.stats import rankdata
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from pipeline.features import CORPUS_PARQUET, KEV_PARQUET, SNAPSHOT_PARQUET
from shared import config
from shared.contracts import EPSS_HISTORY_COLUMNS, TOP500_COLUMNS

SEED = 7
LABEL_HORIZON_DAYS = 310          # longest 2026 horizon: end of Jan 2026 -> Nov 4 2026
TOP_K = 500
TEST_CUTOFF = pd.Timestamp("2026-11-04")
METRICS_JSON = config.PROCESSED_DIR / "backtest_metrics.json"

GENERIC_NAMES = {
    "multiple products", "multiple", "unknown", "n/a", "server", "client", "kernel", "windows server",
    "framework", "platform", "software", "firmware", "router", "routers", "devices", "products",
    "web", "manager", "management", "core", "office", "suite",
}


# --------------------------------------------------------------------------- helpers
def kev_name_matcher(kev: pd.DataFrame, col: str):
    """Regex over KEV vendor/product names plus, for each name, the sorted KEV add dates."""
    names = kev[col].fillna("").str.lower().str.strip()
    dates: dict[str, np.ndarray] = {}
    for name, grp in kev.assign(_n=names).groupby("_n"):
        if len(name) < 3 or name in GENERIC_NAMES:
            continue
        dates[name] = np.sort(pd.to_datetime(grp["date_added"]).values)
    alts = sorted(dates, key=len, reverse=True)
    pattern = re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(a) for a in alts) + r")(?![a-z0-9])")
    return pattern, dates


def asof_kev_counts(desc: pd.Series, asof: np.ndarray, pattern, dates, window_days=None) -> np.ndarray:
    """Max over matched KEV names of the number of KEV entries added before `asof`."""
    out = np.zeros(len(desc))
    for i, (d, t) in enumerate(zip(desc.fillna("").str.lower().values, asof)):
        best = 0
        for name in set(pattern.findall(d)):
            arr = dates[name]
            n = np.searchsorted(arr, t, side="left")
            if window_days is not None:
                n -= np.searchsorted(arr, t - np.timedelta64(window_days, "D"), side="left")
            best = max(best, n)
        out[i] = best
    return out


def prior_document(df: pd.DataFrame) -> pd.Series:
    """Description plus tokens for CWE, assigner and CVSS parts that exist (absence adds nothing)."""
    def toks(row):
        parts = [str(row.description or "")]
        for c in str(row.cwe_ids or "").split(";"):
            if c.strip():
                parts.append("tok_" + c.strip().replace("-", "_").lower())
        if row.assigner:
            parts.append("tok_asg_" + re.sub(r"[^a-z0-9]", "_", str(row.assigner).lower()))
        for col in ["attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope"]:
            v = getattr(row, col)
            if isinstance(v, str) and v:
                parts.append(f"tok_{col}_{v.lower()}")
        return " ".join(parts)
    return df.apply(toks, axis=1)


def fit_prior(corpus: pd.DataFrame, cutoff: pd.Timestamp):
    """Exploitability prior from text/CWE/CVSS parts, using only CVEs published and KEV
    entries added before `cutoff`."""
    train = corpus[corpus.published < cutoff]
    y = (train.kev_date_added.notna() & (train.kev_date_added < cutoff)).astype(int).values
    docs = prior_document(train)
    word = TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=300_000, sublinear_tf=True,
                           token_pattern=r"(?u)\b[\w\.\-]{2,}\b")
    X = word.fit_transform(docs)
    clf = LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000, solver="liblinear")
    clf.fit(X, y)
    return word, clf, int(y.sum()), len(y)


def score_prior(model, df: pd.DataFrame) -> np.ndarray:
    word, clf, *_ = model
    return clf.decision_function(word.transform(prior_document(df)))


# --------------------------------------------------------------------------- features
ORD = {
    "attack_vector": {"NETWORK": 3, "ADJACENT_NETWORK": 2, "LOCAL": 1, "PHYSICAL": 0},
    "attack_complexity": {"LOW": 1, "HIGH": 0},
    "privileges_required": {"NONE": 2, "LOW": 1, "HIGH": 0},
    "user_interaction": {"NONE": 1, "REQUIRED": 0},
    "scope": {"CHANGED": 1, "UNCHANGED": 0},
    "confidentiality_impact": {"HIGH": 2, "LOW": 1, "NONE": 0},
    "integrity_impact": {"HIGH": 2, "LOW": 1, "NONE": 0},
    "availability_impact": {"HIGH": 2, "LOW": 1, "NONE": 0},
}
KEYWORDS = {
    "kw_exploited": r"exploited in the wild|may have been exploited|actively exploited|exploitation in the wild|has been exploited",
    "kw_rce": r"remote code execution|execute arbitrary code|arbitrary code execution|code execution",
    "kw_unauth": r"unauthenticated|without authentication|pre-auth|unauthorized remote",
    "kw_authbypass": r"authentication bypass|bypass authentication|bypass the authentication",
    "kw_cmdinj": r"command injection|os command|inject commands|arbitrary commands",
    "kw_traversal": r"path traversal|directory traversal",
    "kw_deserial": r"deserializ",
    "kw_privesc": r"elevation of privilege|privilege escalation|escalate privileges",
    "kw_memory": r"use-after-free|use after free|out-of-bounds write|type confusion|heap overflow|buffer overflow",
    "kw_wordpress": r"wordpress|plugin for wordpress",
    "kw_edge": r"vpn|firewall|gateway|connect secure|fortios|pan-os|netscaler|sslvpn|ssl vpn|router",
    "kw_xss": r"cross-site scripting|xss",
    "kw_dos": r"denial of service",
}
FEATURES = [
    "epss", "epss_pct", "exploitdb", "metasploit", "nuclei", "poc_github", "n_exploit_flags",
    "days_observed", "horizon_days", "prior_score", "cvss_base",
    *ORD.keys(),
    "assigner_kev_cum", "assigner_kev_12m", "assigner_kev_rate", "assigner_pub_12m",
    "assigner_epss_mean", "assigner_poc_rate",
    "vendor_kev_cum", "vendor_kev_12m", "product_kev_cum", "product_kev_12m",
    "desc_len", *KEYWORDS.keys(),
]


def build_features(snap: pd.DataFrame, kev: pd.DataFrame, impute: dict) -> pd.DataFrame:
    df = snap.copy()
    for c in ["epss", "epss_pct", "cvss3_score", "cvss4_score", "cvss2_score", "assigner_kev_cum",
              "assigner_kev_12m", "assigner_pub_cum", "assigner_pub_12m", "assigner_epss_mean",
              "assigner_poc_rate"]:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype(float)
    flags = ["exploitdb", "metasploit", "nuclei", "poc_github"]
    df[flags] = df[flags].astype(float)
    df["n_exploit_flags"] = df[flags].sum(axis=1)
    df["days_observed"] = df["days_observed"].astype(float)
    # Missing CVSS is a 2026 leak (NIST scores attacked CVEs first), so impute without an indicator.
    df["cvss_base"] = df.cvss3_score.fillna(df.cvss4_score).fillna(df.cvss2_score).fillna(impute["cvss_base"])
    for col, mapping in ORD.items():
        df[col] = df[col].map(mapping).astype(float).fillna(impute[col])
    df["assigner_kev_cum"] = df.assigner_kev_cum.fillna(0)
    df["assigner_kev_12m"] = df.assigner_kev_12m.fillna(0)
    df["assigner_kev_rate"] = (df.assigner_kev_cum + 0.1) / (df.assigner_pub_cum.fillna(0) + 100)
    df["assigner_pub_12m"] = df.assigner_pub_12m.fillna(0)

    # KEV entries strictly before the snapshot month (the KEV file stops at 2025-12-31).
    asof = np.minimum(df.snapshot_month.values.astype("datetime64[ns]"), np.datetime64("2026-01-01", "ns"))
    vp, vd = kev_name_matcher(kev, "vendor")
    pp, pdd = kev_name_matcher(kev, "product")
    df["vendor_kev_cum"] = asof_kev_counts(df.description, asof, vp, vd)
    df["vendor_kev_12m"] = asof_kev_counts(df.description, asof, vp, vd, 365)
    df["product_kev_cum"] = asof_kev_counts(df.description, asof, pp, pdd)
    df["product_kev_12m"] = asof_kev_counts(df.description, asof, pp, pdd, 365)

    low = df.description.fillna("").str.lower()
    df["desc_len"] = low.str.len().astype(float)
    for k, pat in KEYWORDS.items():
        df[k] = low.str.contains(pat, regex=True).astype(int)
    return df


def label_rows(df: pd.DataFrame, knowledge_cutoff: pd.Timestamp) -> pd.DataFrame:
    """Training labels using only KEV entries added before `knowledge_cutoff`."""
    last_known = knowledge_cutoff - pd.Timedelta(days=1)
    out = df[df.snapshot_end < last_known].copy()
    label_end = (out.snapshot_end + pd.Timedelta(days=LABEL_HORIZON_DAYS)).clip(upper=last_known)
    out["horizon_days"] = (label_end - out.snapshot_end).dt.days.astype(float)
    kd = out.kev_date_added
    out["label"] = (kd.notna() & (kd > out.snapshot_end) & (kd <= label_end)).astype(int)
    return out


# --------------------------------------------------------------------------- models
# The full FEATURES list overfit the ~40-110 positives (backtest 15 hits at 500 for LightGBM on all
# features vs 16-18 on this set), so the trees use a compact set. Monotone constraints say
# "more exploit evidence never lowers the score".
MODEL_FEATURES = [
    "epss", "epss_pct", "n_exploit_flags", "poc_github", "nuclei", "metasploit", "exploitdb",
    "prior_score", "vendor_kev_cum", "product_kev_12m", "assigner_kev_rate", "kw_exploited",
    "days_observed", "horizon_days",
]
MONOTONE = [0 if c in ("days_observed", "horizon_days") else 1 for c in MODEL_FEATURES]
LOG_COLS = ["vendor_kev_cum", "product_kev_12m"]


def logit_matrix(df: pd.DataFrame) -> pd.DataFrame:
    X = df[MODEL_FEATURES].copy()
    X["epss"] = np.log(X.epss.fillna(0) + 1e-4)
    X["assigner_kev_rate"] = np.log(X.assigner_kev_rate)
    for c in LOG_COLS:
        X[c] = np.log1p(X[c])
    return X.fillna(0)


def fit_ensemble(train: pd.DataFrame):
    X, y = train[MODEL_FEATURES], train.label.values
    lgbs, xgbs = [], []
    for s in range(5):  # seed bagging: few positives, so average several noisy models
        m = lgb.LGBMClassifier(
            n_estimators=300, learning_rate=0.02, num_leaves=5, min_child_samples=50,
            subsample=0.8, subsample_freq=1, colsample_bytree=0.8, reg_lambda=10.0,
            monotone_constraints=MONOTONE, random_state=SEED + s, verbose=-1)
        m.fit(X, y)
        lgbs.append(m)
        x = xgb.XGBClassifier(
            n_estimators=300, learning_rate=0.02, max_depth=3, min_child_weight=1,
            subsample=0.8, colsample_bytree=0.8, reg_lambda=10.0, scale_pos_weight=20.0,
            random_state=SEED + s, tree_method="hist")
        x.fit(X, y)
        xgbs.append(x)
    L = logit_matrix(train)
    mu, sd = L.mean(), L.std() + 1e-9
    logit = LogisticRegression(C=0.1, class_weight="balanced", max_iter=2000).fit((L - mu) / sd, y)
    return lgbs, xgbs, (logit, mu, sd)


def rank01(a: np.ndarray) -> np.ndarray:
    return rankdata(a) / len(a)


def predict_ensemble(models, df: pd.DataFrame) -> dict[str, np.ndarray]:
    lgbs, xgbs, (logit, mu, sd) = models
    X = df[MODEL_FEATURES]
    p_lgb = np.mean([m.predict_proba(X)[:, 1] for m in lgbs], axis=0)
    p_xgb = np.mean([m.predict_proba(X)[:, 1] for m in xgbs], axis=0)
    p_log = logit.decision_function((logit_matrix(df) - mu) / sd)
    rule = baselines(df)["public_exploit_then_epss"]
    # Equal-weight rank average of three learners plus the strongest rule-based baseline.
    ens = (rank01(p_lgb) + rank01(p_xgb) + rank01(p_log) + rank01(rule)) / 4
    return {"lightgbm": p_lgb, "xgboost": p_xgb, "logistic": p_log,
            "prior_only": df.prior_score.values, "ensemble": ens}


def hits(score: np.ndarray, y: np.ndarray, k: int) -> int:
    order = np.argsort(-score, kind="stable")
    return int(y[order[:k]].sum())


def baselines(df: pd.DataFrame) -> dict[str, np.ndarray]:
    epss = df.epss.fillna(0).values
    poc = (df.n_exploit_flags > 0).astype(float).values
    return {
        "cvss3_first": pd.to_numeric(df.cvss3_score, errors="coerce").fillna(-1).values + 1e-6 * epss,
        "epss_first": epss,
        "public_exploit_then_epss": poc * 10 + epss,
    }


# --------------------------------------------------------------------------- main
def main() -> None:
    snap = pd.read_parquet(SNAPSHOT_PARQUET)
    corpus = pd.read_parquet(CORPUS_PARQUET)
    kev = pd.read_parquet(KEV_PARQUET)
    for d in (snap, corpus):
        d["published"] = pd.to_datetime(d.published)
        d["kev_date_added"] = pd.to_datetime(d.kev_date_added)
    snap["snapshot_month"] = pd.to_datetime(snap.snapshot_month)
    snap["snapshot_end"] = pd.to_datetime(snap.snapshot_end)

    # Imputation values come from pre-2026 rows only.
    hist = snap[~snap.is_2026]
    impute = {"cvss_base": float(pd.to_numeric(hist.cvss3_score, errors="coerce").median())}
    for col, mapping in ORD.items():
        impute[col] = float(hist[col].map(mapping).mode().iloc[0])

    # Exploitability prior, refit "as of" each January so every row is scored out of time.
    snap["prior_score"] = np.nan
    year = snap.snapshot_month.dt.year.values
    for y in (2024, 2025, 2026):
        cutoff = pd.Timestamp(f"{y}-01-01")
        model = fit_prior(corpus, cutoff)
        mask = year == y
        snap.loc[mask, "prior_score"] = score_prior(model, snap[mask])
        print(f"prior as of {cutoff.date()}: {model[2]} KEV positives / {model[3]} CVEs; scored {mask.sum()} rows")

    feats = build_features(snap, kev, impute)
    feats.drop(columns=["description"]).to_parquet(config.PROCESSED_DIR / "model_features.parquet")
    feats_hist = feats[~feats.is_2026]
    n_2026 = int(feats.is_2026.sum())

    # ---------------- Backtest: pretend it is 2025-01-01, rank the 2025 mirror of the benchmark.
    bt_train = label_rows(feats_hist[feats_hist.snapshot_month < "2025-01-01"], pd.Timestamp("2025-01-01"))
    bt_test = feats_hist[(feats_hist.snapshot_month >= "2025-01-01")
                         & (feats_hist.published < "2025-10-01")].copy()
    kd, end = bt_test.kev_date_added, bt_test.snapshot_end
    bt_test["label"] = (kd.notna() & (kd > end) & (kd <= pd.Timestamp("2025-11-04"))).astype(int)
    bt_test["horizon_days"] = (pd.Timestamp("2025-11-04") - end).dt.days.astype(float)
    print(f"backtest train rows {len(bt_train)} (pos {bt_train.label.sum()}), "
          f"test rows {len(bt_test)} (pos {bt_test.label.sum()})")
    models = fit_ensemble(bt_train)
    scores = {**baselines(bt_test), **predict_ensemble(models, bt_test)}
    # 2026 has ~2x the rows, so 500 of 72,670 is the same share as ~243 of the 2025 mirror.
    k_scaled = round(TOP_K * len(bt_test) / n_2026)
    y_bt = bt_test.label.values
    metrics = {
        "backtest": "train on 2024 snapshots with KEV known to 2024-12-31; test on CVEs published Jan-Sep 2025, "
                    "snapshot rules as 2026, label = added to KEV by 2025-11-04",
        "test_rows": int(len(bt_test)), "test_positives": int(y_bt.sum()),
        "k_scaled_equivalent_of_top500": k_scaled,
        "hits_at_500": {n: hits(s, y_bt, 500) for n, s in scores.items()},
        f"hits_at_{k_scaled}": {n: hits(s, y_bt, k_scaled) for n, s in scores.items()},
        "hits_at_1000": {n: hits(s, y_bt, 1000) for n, s in scores.items()},
    }
    print(json.dumps(metrics, indent=2))

    # ---------------- Final: knowledge cutoff 2025-12-31, train on all 2024-2025 snapshots.
    final_train = label_rows(feats_hist, pd.Timestamp("2026-01-01"))
    test = feats[feats.is_2026].copy()
    test["horizon_days"] = (TEST_CUTOFF - test.snapshot_end).dt.days.astype(float)
    print(f"final train rows {len(final_train)} (pos {final_train.label.sum()}), 2026 rows {len(test)}")
    models = fit_ensemble(final_train)
    test["score"] = predict_ensemble(models, test)["ensemble"]

    imp = pd.Series(np.mean([m.feature_importances_ for m in models[0]], axis=0), index=MODEL_FEATURES)
    metrics["logistic_coefficients"] = dict(zip(MODEL_FEATURES, models[2][0].coef_[0].round(3).tolist()))
    metrics["final_train_rows"] = int(len(final_train))
    metrics["final_train_positives"] = int(final_train.label.sum())
    metrics["lightgbm_split_importance"] = imp.sort_values(ascending=False).round(1).to_dict()
    METRICS_JSON.write_text(json.dumps(metrics, indent=2))

    top = test.sort_values("score", ascending=False).head(TOP_K).reset_index(drop=True)
    top["rank"] = top.index + 1
    top["cvss"] = pd.to_numeric(top.cvss3_score, errors="coerce").fillna(pd.to_numeric(top.cvss4_score, errors="coerce"))
    top["epss_momentum"] = np.nan  # 2026 has one EPSS value per CVE (snapshot month only)
    # Upper bound: exploit code existed by the end of the snapshot month.
    top["poc_lag_days"] = np.where(top.n_exploit_flags > 0, top.days_observed, np.nan)
    top["published_date"] = top.published.dt.strftime("%Y-%m-%d")
    top[TOP500_COLUMNS].to_csv(config.TOP500_CSV, index=False)
    top[["cve_id"]].to_csv(config.PROCESSED_DIR / "top500_submission.csv", index=False)
    hist_out = top[["cve_id"]].assign(month=top.snapshot_month.dt.strftime("%Y-%m-01"), epss=top.epss)
    hist_out[EPSS_HISTORY_COLUMNS].to_csv(config.EPSS_HISTORY_CSV, index=False)
    print(f"Wrote {config.TOP500_CSV} and {config.EPSS_HISTORY_CSV}")


if __name__ == "__main__":
    main()
