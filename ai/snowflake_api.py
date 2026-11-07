"""Minimal client for the Snowflake SQL REST API (/api/v2/statements) with key-pair JWT auth.

Uses the read-only COPILOT_APP user. Pass bindings for any user text; never paste it into SQL.
"""
import base64
import hashlib
import time

import pandas as pd

from ai.common import SF_ACCOUNT, SF_APP_KEY, SF_DATABASE, SF_SCHEMA, SF_WAREHOUSE, private_key


class SnowflakeSQLAPI:
    def __init__(self, user="COPILOT_APP", key_path=None, role="COPILOT_READER"):
        self.user, self.role = user.upper(), role
        self.key = private_key(key_path or SF_APP_KEY)
        self.account = SF_ACCOUNT.upper()
        self.host = f"https://{SF_ACCOUNT.lower().replace('_', '-')}.snowflakecomputing.com"
        self._jwt, self._exp = None, 0

    def _token(self):
        import jwt
        from cryptography.hazmat.primitives import serialization
        if time.time() < self._exp:
            return self._jwt
        pub = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(pub).digest()).decode()
        qualified = f"{self.account}.{self.user}"
        now = int(time.time())
        self._jwt = jwt.encode({"iss": f"{qualified}.{fingerprint}", "sub": qualified,
                                "iat": now, "exp": now + 3500}, self.key, algorithm="RS256")
        self._exp = now + 3000
        return self._jwt

    def query(self, statement, bindings=None) -> pd.DataFrame:
        import requests
        body = {"statement": statement, "timeout": 30, "warehouse": SF_WAREHOUSE,
                "role": self.role, "database": SF_DATABASE, "schema": SF_SCHEMA}
        if bindings:
            body["bindings"] = bindings
        r = requests.post(f"{self.host}/api/v2/statements", json=body, timeout=60, headers={
            "Authorization": f"Bearer {self._token()}",
            "X-Snowflake-Authorization-Token-Type": "KEYPAIR_JWT",
            "Content-Type": "application/json", "Accept": "application/json"})
        if r.status_code != 200:
            raise RuntimeError(f"Snowflake {r.status_code}: {r.text[:500]}")
        j = r.json()
        cols = [c["name"] for c in j["resultSetMetaData"]["rowType"]]
        return pd.DataFrame(j.get("data", []), columns=cols)
