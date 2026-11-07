# GraniteGuard demo — target 2 minutes 40 seconds

Use real handoffs when available. If showing samples, keep the synthetic banner visible and say so. Replace placeholders with verified results before recording. Do not claim integrations succeeded without showing evidence.

| Time | Show | Narration |
|---|---|---|
| 0:00–0:20 | Dashboard title and queue | Security teams face more vulnerabilities than they can patch. Severity tells us how damaging an issue could be. Our question is different: which vulnerabilities should engineers investigate and fix first? This is GraniteGuard. |
| 0:20–0:45 | Review budget, search, ranked table | We turn a ranking into a practical review queue. Set the team's review budget, search a CVE, and inspect its model score alongside CVSS and EPSS. The model score orders the queue; we do not present it as a calibrated probability. |
| 0:45–1:10 | Select a CVE with history | This monthly EPSS history shows how a signal evolves. Our intended Tiger Data pipeline supplies temporal features, and the dashboard reads its export. Every prediction must respect the vulnerability's snapshot cutoff. [If verified: briefly show the actual Tiger Data query.] |
| 1:10–1:35 | Threat brief plus real Granite run evidence | IBM Granite is our explanation layer. It turns supplied context into a short prioritization brief. [Show actual model ID and output.] The engineer can inspect the signals rather than rely on a score alone. Generated explanations still require review. |
| 1:35–1:55 | Open Copilot; submit one prepared question | The Snowflake Copilot uses the selected CVE's description and brief to answer a focused question. [Show a verified response, or state: this connection is pending and we are showing the offline state.] Source-cited mitigation retrieval is a next step. |
| 1:55–2:20 | Method panel and verified evaluation slide | We compare against CVSS and EPSS on the same candidate set and temporal holdout. [Insert verified hits at 500.] We audit later-added NIST fields for leakage. Absence from KEV is not proof that a vulnerability was never exploited. |
| 2:20–2:40 | Submission export and closing view | The final export contains exactly 500 eligible CVE IDs. GraniteGuard brings ranking, evidence, and explanations into one review workflow so a security team can spend its next hour on a more informed decision. |

## Recording checklist
- Use a readable browser zoom, hide notifications and secrets, and test microphone audio.
- Choose a CVE with a populated history and a verified Granite brief before recording.
- Rehearse the Copilot question and verify the service connection. Show offline status honestly if unavailable.
- If evaluation is unfinished, replace the results line with: Our evaluation is pending; these screens demonstrate the product workflow.
- If the data is synthetic, say at the start: This walkthrough uses clearly labelled synthetic data.
- Record one 160-second take, trim pauses, and confirm the final file is between 2 and 3 minutes.
- Verify video accessibility, repository URL, IBM evidence, and CSV attachment before submitting.

This is a recording script; no video recording has been produced by these project changes.
