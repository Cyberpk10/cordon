# Aegis phishing classifier — model card

**Version**: `m3-logreg-v1-20261006` · see `metrics.json` in this directory for the full
machine-readable evaluation. Published artifacts (`classifier.joblib`, `vectorizer.joblib`,
`metadata.json`) live in `backend/app/ml/artifacts/` — see that directory's note on why, and
`backend/app/ml/classifier.py` for how they're loaded at inference time.

**2026-10-06 retrain**: broadened real-data coverage (Nazario's yearly 2015-2025 phishing files,
two more SpamAssassin ham archives) and added a small, bounded synthetic-augmentation slice. See
"Honest before/after/ablation evaluation" below for exactly what changed and what didn't, and
`ml/corpus/sources.md` for full provenance of every source added.

## What this is

A secondary ML signal that nudges Aegis's rule-based phishing risk score, gated behind
`ENABLE_ML_CLASSIFIER` (default off). It is **not** a standalone verdict engine — the rule-based
indicator engine (`backend/app/indicators/`) remains the primary decision surface. See
`backend/app/scoring/risk_engine.py` for the bounded blend formula that makes this structurally
true (the ML signal alone can never push a case from `SAFE` to `MALICIOUS`).

## Data

Trained on the corpus assembled in `ml/aegis_ml/` — see `ml/corpus/sources.md` for full
provenance/licensing. Summary (post-dedupe, stratified 70/15/15 split over the **real** rows,
split before any feature fitting to avoid leakage; synthetic rows are appended to train only —
see "Synthetic augmentation" below):

| split | total | phishing | benign |
|-------|------:|---------:|-------:|
| train | 9,739 |    2,536 |  7,203 |
| val   | 2,050 |      506 |  1,544 |
| test  | 2,049 |      505 |  1,544 |

Sources: Nazario phishing corpus, now including the yearly 2015-2025 files (phishing), SpamAssassin
public corpus ham subset (now 5 archives spanning 2002-2003) + an Enron `_sent_mail` sample
(benign), plus bounded synthetic augmentation (phishing — see below). Class imbalance (~26%
phishing, up from ~13% before the 2026-10-06 broadening) reflects the real-world sources rather
than deliberate rebalancing; `class_weight="balanced"` is used at training time to compensate.

### Synthetic augmentation

180 of the 9,739 train rows (**1.85%**, `metrics.json`'s `data_composition.train_synthetic_fraction`)
are LLM-generated synthetic phishing/BEC/AI-lure emails (`source` prefixed `synthetic_`), added to
cover attack patterns thin or absent in the real public corpora (BEC, AI-generated-style lures —
see `ml/corpus/sources.md`'s "Synthetic augmentation" section for full methodology). Three
structural guarantees, not conventions:

1. **Bounded** — a named constant (`DEFAULT_TARGET_PER_CATEGORY = 60` × 3 categories) caps the
   volume regardless of how large the real corpus grows.
2. **Train-only** — `aegis_ml/split.py` routes every `synthetic_*`-sourced row into `train` and
   structurally excludes it from `val`/`test`'s stratification (`ml/tests/test_split.py` has
   dedicated tests for this). Every metric below is measured against a **real-only** holdout.
3. **Labeled** — every synthetic row's `source` column and every generated `.eml`'s
   `X-Aegis-Synthetic*` headers mark it as synthetic; none of that marking reaches the model's
   actual feature space (verified by inspection — see `ml/corpus/sources.md`), so it can't become
   a shortcut "tell" the model learns instead of real content signal.

## Features

Two halves, concatenated into one sparse matrix (`backend/app/ml/features.py` is the single
source of truth for the structured half — shared by training and real-time inference, so it
cannot drift):

- **Structured (23 columns)**: one feature per email-relevant rule-based indicator id (its score
  if it fired, else 0 — see `INDICATOR_FEATURE_IDS` in `backend/app/ml/features.py`), plus
  `total_rule_score`, `indicator_count`, `link_count`, `attachment_count`, `body_length_log`.
- **Text (up to 5,000 columns)**: TF-IDF over `subject + " " + body_text`, English stop words
  removed, fit **only on the train split** (`ml/aegis_ml/features.py::fit_vectorizer`) — val/test
  are only ever transformed with this fitted vectorizer, never refit, to avoid leakage.

Every record is re-parsed from its raw original bytes through the real backend parser
(`app.parsing.eml_parser.parse_eml`) and indicator engine (`app.indicators.engine.run_indicators`)
before feature extraction — not reconstructed from the corpus's own lightweight fields — so
training-time features are guaranteed identical in shape and derivation to what a live request
produces.

## Model

`LogisticRegression(class_weight="balanced", penalty="l2")` wrapped in
`CalibratedClassifierCV(method="sigmoid", cv=5)` for well-calibrated probabilities (chosen over
gradient boosting: the feature space is TF-IDF-dominated — thousands of sparse dimensions — which
a linear model fits and calibrates more predictably than a tree ensemble, without adding a new
third-party boosting dependency).

## Honest before/after/ablation evaluation (held-out test split, never touched during training or threshold tuning)

Three models, same training pipeline, same real-only test split construction (test composition
differs between "before" and the two "after" rows only because the real corpus itself grew —
synthetic rows can never reach test regardless of which model):

| model | test size (phish/benign) | precision | recall | F1 | ROC-AUC | FP / FN |
|---|---|---:|---:|---:|---:|---|
| **Before** (2026-08-12, Nazario-classic + SpamAssassin-3-archives + Enron, no synthetic) | 1,744 (230/1,514) | 0.991 | 0.952 | 0.971 | 0.995 | 2 / 11 |
| **After, real-only ablation** (2026-10-06, + Nazario yearly + 2 more SpamAssassin archives, **no synthetic**) | 2,049 (505/1,544) | 0.978 | 0.976 | 0.977 | 0.9991 | 11 / 12 |
| **After, real + synthetic (shipped)** (2026-10-06, same real data + 180 bounded synthetic rows in train) | 2,049 (505/1,544) | 0.978 | 0.976 | 0.977 | 0.9991 | 11 / 12 |

All at the default 0.5 probability threshold. Reading this honestly:

- **Broadening real data (row 2 vs. row 1) is the change that actually moved metrics.** Recall
  rose (0.952 → 0.976) and ROC-AUC improved; precision dropped slightly (0.991 → 0.978) and raw
  false positives rose 2 → 11. The test set itself changed too (505 vs. 230 phishing examples, and
  benign now includes the intentionally-adversarial SpamAssassin `hard_ham` archives, which are
  designed to be hard to tell apart from spam) — so this isn't a like-for-like regression, it's a
  harder, more representative test catching more (including modern, 2015-2025-era) phishing at a
  modest precision cost. FP rate: 11/1,544 = 0.71% (up from 2/1,514 = 0.13%), still low in absolute
  terms.
- **Adding the bounded synthetic slice (row 3 vs. row 2) changed nothing measurable on this real
  test set** — identical precision, recall, F1, and confusion matrix; ROC-AUC differs in the 4th
  decimal place (0.99912 vs. 0.99914). At 1.85% of train, this is the expected result: not enough
  rows to move aggregate metrics on a test distribution the synthetic categories weren't
  specifically designed to resemble. It is **not** evidence the augmentation helped generalization
  to novel attacks — this evaluation structurally cannot show that, since the synthetic categories
  (BEC, AI-lure) have no real-source analog in this same test set to compare against. What it does
  show, per the task's explicit requirement: no regression. Precision did not drop, no new false
  positives appeared, and the separate benign-control guardrail test
  (`backend/tests/integration/test_ml_guardrail.py`) still passes at zero false positives. Per
  instruction, there was nothing to "dial back."
- **Synthetic-tell check**: confirmed by code inspection (not just by this metric match) that the
  `X-Aegis-Synthetic*` marker headers never reach the structured or TF-IDF feature space — see
  `ml/corpus/sources.md`. The identical metrics above are consistent with (though don't by
  themselves prove) the model not having learned a synthetic-specific shortcut; the header-leakage
  check is the stronger, structural guarantee.
- **Shipped model**: the real+synthetic model (row 3) — identical measured performance to
  real-only, plus whatever unmeasured generalization benefit the synthetic BEC/AI-lure categories
  provide against attack patterns this specific real test set doesn't contain examples of.

### High-precision decision threshold

Tuned on the **val** split (not test, to avoid tuning-on-test leakage) as the lowest probability
cutoff that clears a phishing-class precision target of ≥0.95 — chosen because a false positive
here means telling an analyst a benign email is phishing, which is what erodes trust in the tool
fastest, so precision is favored over recall when trading off.

- **Threshold: 0.18** (shipped model) — val precision 0.950, recall 0.984 (target met).
- Re-reported on test (informational only, not used for tuning): precision 0.947, recall 0.990.
- Before (2026-08-12): threshold 0.16, val precision 0.954/recall 0.987; test precision
  0.941/recall 0.978.

This threshold is for anyone wanting to use the model as a standalone high-precision gate — it is
**not** the mechanism used by the backend integration, which blends the raw probability directly
into the risk score via a bounded, symmetric nudge (see `risk_engine.py`) rather than a hard
cutoff.

## Limitations

- Real-data coverage now extends through 2025 (Nazario's yearly files), a real improvement over
  the prior 2000s-2015-only vintage — but QR-code phishing and AI-generated lures are still not
  well-represented in the **real** data; the only exposure to an AI-lure *pattern* at all is the
  60-row `synthetic_ai_lure` category, which is LLM-generated, not real attack traffic, and whose
  actual effect on generalization to real AI-generated lures is unmeasured (see the honest
  evaluation above — this corpus has no real-source AI-lure examples to test that claim against).
- The benign class now includes SpamAssassin's `hard_ham` archives (intentionally
  spam-adjacent-looking legitimate mail) — a harder, more realistic benign distribution than
  before, but also the most likely explanation for the raw false-positive count rising from 2 to
  11 on the broadened test set (see evaluation table).
- No real, standalone BEC corpus exists publicly (checked — see `ml/corpus/sources.md`'s "Sources
  investigated and NOT used"); this model's only BEC-pattern exposure is the 60-row synthetic BEC
  category.
- Binary label only (`phishing` / `benign`) — no public source provides a `suspicious` middle
  class, so this model cannot itself distinguish "borderline" from "clearly benign."
- English-language text bias — TF-IDF stop words and the source corpora are English-only;
  non-English phishing emails will get little signal from the text half.
- `from_addr` may be unreliable for a small fraction of Enron messages per a documented header-
  spoofing caveat in `ml/corpus/sources.md` — this affects a benign-class feature only, not the
  phishing class.

## Intended use

A secondary, bounded signal inside Aegis's existing rule-based email risk scoring — never a
replacement for the indicator engine, and never exposed as a standalone verdict. Retrain (and
re-publish this card) whenever `backend/app/indicators/` gains or changes rules that the
structured feature list depends on, or when the corpus is meaningfully refreshed with more recent
phishing samples.
