"""Fixed, hardcoded overlay mapping human-risk (phishing-simulation) evidence onto the
subset of framework controls it's relevant to (M9 Stage 2) — deliberately separate from
each framework YAML's `mappings:` section (app/mapping/frameworks/*.yaml), which maps real
analysis *indicator IDs* to controls. There is no analogous "indicator" concept for a
phishing-simulation campaign, so this is a small, fixed Python overlay instead of a dynamic
per-indicator mapping.

PR.AT-01 (NIST CSF 2.0) and A.6.3 (ISO/IEC 27001:2022) already existed before Stage 2 — no
YAML edit was needed for those two. SOC 2's CC1.4 was added in this stage specifically for
this mapping (see app/mapping/frameworks/soc2.yaml).
"""

from __future__ import annotations

HUMAN_RISK_CONTROL_IDS: dict[str, list[str]] = {
    "nist_csf": ["PR.AT-01"],
    "iso_27001": ["A.6.3"],
    "soc2": ["CC1.4", "CC2.2"],
}
