# Corpus sources, provenance, and licenses

All availability/terms below were verified live on **2026-08-07** while building this pipeline
(`ml/aegis_ml/download/`), with a second pass on **2026-10-06** that extended real-data coverage
(Nazario yearly files, two more SpamAssassin archives) and added bounded synthetic augmentation.
Re-verify before relying on this for anything beyond internal defensive research — dataset hosting
and terms can and do change. Raw data itself is never committed (see root `.gitignore` —
`ml/data/` and `ml/models/`); this file is the durable record of what was used and under what
terms.

## Nazario phishing corpus — `label=phishing`, `source=nazario`

- **Primary**: `https://monkey.org/~jose/phishing/` — `phishing0.mbox`, `phishing1.mbox`,
  `phishing2.mbox`, `phishing3.mbox`, `20051114.mbox`.
- **Fallback**: Wayback Machine, resolved per-file via `https://archive.org/wayback/available`.
  Verified a snapshot of the corpus index from **2026-06-07** listing all the files above as still
  present, plus yearly `phishing-2015` .. `phishing-2025` entries and a `private-phishing4.mbox`.
- **Verification note**: `monkey.org` was unreachable from the sandbox this pipeline was written
  in (`curl` connection refused), while general internet access from the same shell worked fine
  (e.g. `google.com` returned 200) — this looks like a sandbox-specific network policy rather than
  the site being down. The downloader tries monkey.org first and falls back to Wayback
  automatically, so it should work either way depending on where it's actually run.
- **Scope decision (2026-08-07)**: only the 5 classic files above were ingested. The yearly
  `phishing-2015..2025` entries appeared in the directory listing with no file extension — whether
  each is a file or a subdirectory wasn't confirmed, so they were **not** ingested in Stage 1 rather
  than risk silently saving an HTML directory listing as if it were mbox content. `private-phishing4.mbox`
  is excluded (access-restricted).
- **Yearly extension (2026-10-06)**: re-verified via the live Apache directory listing (through
  Wayback) that each `phishing-2015` .. `phishing-2025` entry is a plain file with a real, distinct
  byte size (an Apache directory entry would show no size) — not a subdirectory. Spot-checked
  `phishing-2023` by actually downloading and inspecting it: real mbox content, "From "-delimited,
  real headers, a 2023-dated DKIM-signed phishing message. This is the single biggest lever
  available for the model card's documented "2000s-2015 era" staleness limitation, since it's 10+
  more years from the exact same already-vetted source/maintainer/convention, not a new source to
  separately clear. `python -m aegis_ml.cli build` now fetches `phishing-2015` through
  `phishing-2025` by default (`include_yearly=True`); `phishing-2025` has no Wayback snapshot yet as
  of this writing (too recent) and is silently skipped the same way any other temporarily-unavailable
  file would be — not an error, and expected to start succeeding on its own once archive.org crawls
  it. `private-phishing4.mbox` remains excluded.
  - **Downloader note**: the Wayback fallback (`_try_wayback` in `aegis_ml/download/nazario.py`)
    requests the content-serving endpoint directly with a generic/future timestamp (which
    302-redirects to the closest real snapshot) rather than first resolving an exact snapshot via
    the separate `/wayback/available` lookup API. That lookup API proved aggressively,
    persistently rate-limited (HTTP 429, still failing after minutes of backoff) under this
    project's own repeated research calls to it during this session; the content endpoint itself
    is not subject to the same limit.
- **License/terms**: no `LICENSE.txt` content was retrievable as of 2026-08-07 (the file was linked
  from the index but wasn't itself archived). As of the 2026-10-06 pass, a `LICENSE.txt` *does* now
  exist on the live site (confirmed via the directory listing, 18KB) — but monkey.org itself remained
  unreachable from this sandbox and no Wayback snapshot of that specific file exists yet, so its
  actual terms **could not be read this session**. This is an honest, currently-open gap, not a
  clearance: re-check `LICENSE.txt` before treating this corpus's terms as fully resolved.
  `README.txt` (fetched via Wayback, 2025-07-17 snapshot) states the corpus is hand-classified by
  Jose Nazario from his personal inbox, "not meant to be exhaustive but rather representative,"
  explicitly **should not contain malware** (e.g. malicious executable attachments), and that
  earlier mailboxes were anonymized (destination IPs/domains) while later ones were not. No formal
  reuse license is stated; used under the long-standing research-use convention this corpus has
  been cited under in the security literature (widely cited — see Google Scholar for "nazario
  phishingcorpus"). The maintainer's README says he'd "love to get a peek" at resulting
  publications.
- **Alternate mirror (not used by the script, documented for manual fallback)**: Academic Torrents,
  `https://academictorrents.com/details/a77cda9a9d89a60dbdfbe581adf6e2df9197995a` — 4,555 `.eml`
  files, 37.48MB, a third-party 2015 re-upload of the same corpus. No explicit license stated. Would
  need a BitTorrent client; intentionally not scripted here to avoid that dependency.

## SpamAssassin public corpus (ham subset) — `label=benign`, `source=spamassassin`

- **URL**: `https://spamassassin.apache.org/old/publiccorpus/` — confirmed live, file listing
  scraped directly at verification time.
- **Files used**: `20030228_easy_ham.tar.bz2` (2,500 messages), `20030228_hard_ham.tar.bz2` (250
  messages), `20030228_easy_ham_2.tar.bz2` (1,400 messages) — 4,150 benign messages total from the
  2026-08-07 pass. Extended 2026-10-06 with two more archives from the same already-cleared
  host/terms: `20021010_easy_ham.tar.bz2` and `20021010_hard_ham.tar.bz2` (an earlier 2002 ham/hard-ham
  pair, same maintainer and public-corpus page). The `spam`/`spam_2` archives in the same listing
  remain **not** used (not needed for this corpus). Each archive now extracts into a
  date-qualified subdirectory (`ml/data/raw/spamassassin/<date>/<category>/`) so the two
  same-named `easy_ham`/`hard_ham` folders from different dates don't collide.
- **License/terms** (from the live README): copyright for message text "remains with the original
  senders." Explicit restriction: **"Do NOT send these emails into a live email system"** (avoids
  bounce-back to real addresses in the corpus). Messages were sourced from public forums, submitters
  who gave explicit consent, the maintainer's personal correspondence, and public newsletters; some
  address obfuscation was applied for privacy. Offered specifically for spam-filter research/testing.
  The maintainer requests notification if the corpus is used in academic papers.

## Enron email dataset (subset) — `label=benign`, `source=enron`

- **URL**: `https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz` — confirmed live
  (HTTP 200, `Content-Length: 423254787`, no auth).
- **Subset taken**: rather than extracting the full archive (~500k messages across 150 custodians),
  the pipeline streams the `.tar.gz` directly and reservoir-samples a configurable number of
  messages (default 6,000, seed 42) from each custodian's `_sent_mail/` folder only — mail the
  custodian personally wrote, a cleaner "legitimate business email" signal than inbox/received mail.
  The full ~423MB still has to be transferred once (CMU doesn't offer partial/range downloads of a
  subset); only the sampled subset is written to `ml/data/raw/enron/`.
- **License/terms**: no explicit license stated on the page. The dataset was originally made public
  via the Federal Energy Regulatory Commission's investigation into Enron and has been hosted by CMU
  since; the page asks users to **"be sensitive to the privacy of the people involved,"** notes that
  attachments are excluded and some messages were redacted at affected employees' request. Widely
  treated in the research community as the standard public "real" email corpus given the lack of
  comparable alternatives.
- **Caveat**: the CMU page notes a 2026 disclosure about possible header-spoofing/impersonation in
  parts of the corpus. This doesn't block using it as benign training data here (the content itself
  is genuine internal business correspondence), but `from_addr` may be unreliable for a small
  fraction of messages — worth remembering if `from_addr` is ever used as a model feature.

## PhishTank — reference-only, **not** part of the unified email corpus

- **URL**: `https://data.phishtank.com/data/online-valid.csv` (redirects to a signed CDN URL) —
  confirmed live and downloadable without registration at verification time (13.5MB CSV, real
  current data). An API key is optional and only raises rate limits; not required for this one-shot
  bulk fetch.
- **Why it's excluded from the corpus schema**: PhishTank's data is URL-only —
  `phish_id, url, phish_detail_url, submission_time, verified, verification_time, online, target` —
  never raw headers, subject, body text, or a from-address. It structurally cannot fill
  `{id, raw_headers, subject, body_text, from_addr, label, source}` with real email content.
  Fabricating placeholder email rows from bare URLs was considered and rejected in favor of keeping
  the training corpus free of non-representative synthetic data (see project decision log / plan).
  `aegis_ml.download.phishtank.download_phishtank_reference()` still fetches the feed to
  `ml/data/raw/phishtank/online-valid.csv` as a standalone reference file for possible future
  URL-reputation feature work (e.g. cross-referencing URLs found inside other emails) — it is never
  read by `normalize.py`/`dedupe.py`/`split.py`.
- **Terms**: operated by Cisco Talos Intelligence Group; PhishTank states the data is free for both
  website and API use. Governed by Cisco's general Terms of Use/Privacy policy — no PhishTank-specific
  bulk-data reuse license text was found beyond that reference.

## Synthetic augmentation (2026-10-06) — `label=phishing`, `source=synthetic_{credential_phishing,bec,ai_lure}`

Not a public corpus — generated in-house via `aegis_ml.synthesize` using an Anthropic model
(forced tool-use, structured output) prompted to produce realistic attack emails across three
categories chosen to cover gaps the real public corpora above don't: credential-phishing
variants, Business Email Compromise (no clean standalone real BEC corpus was found — see
"Sources investigated and NOT used" below), and AI-generated-lure style phishing (the specific
gap the model card's "has not seen AI-generated lures" limitation calls out). Every generated
message targets a clearly fictional organization/domain (`.test` TLD or an obviously-fake brand)
and is defensive-only: no real victim content, no real customer data, nothing exfiltrated or
executed.

- **Bounded by design, not just convention**: `DEFAULT_TARGET_PER_CATEGORY = 60` (180 total
  across the 3 categories) is a named constant chosen so the synthetic volume stays a small
  fraction of the training set regardless of how the real corpus grows — in the 2026-10-06
  training run this was 180 / 9,739 train rows = **1.85%** (`ml/models/metrics.json`'s
  `data_composition.train_synthetic_fraction`), far under any threshold where synthetic content
  could dominate what the model learns.
- **Train-only by construction, not convention**: `aegis_ml/split.py` routes every row whose
  `source` starts with `synthetic_` straight into the train split and excludes it from the
  stratification entirely — synthetic rows structurally cannot land in `val` or `test`. This is
  what makes "evaluated on a held-out real test set" a verifiable fact about how the splits were
  built, not an assertion (see `ml/tests/test_split.py`'s dedicated synthetic-exclusion tests).
- **Clearly labeled, not just segregated**: every generated `.eml` carries `X-Aegis-Synthetic:
  true`, `X-Aegis-Synthetic-Category`, and `X-Aegis-Synthetic-Technique` headers, and each row's
  `source` column names its category explicitly — so synthetic vs. real composition is always
  inspectable and the two populations' effect can be measured separately (see "Honest before/after
  evaluation" in `ml/models/CARD.md`).
- **Checked for leakage into features**: `aegis_ml/features.py` builds the model's inputs by
  re-parsing each record's raw bytes through the real backend pipeline
  (`app.parsing.eml_parser.parse_eml()` + `app.indicators.engine.run_indicators()` +
  `app.ml.features.build_structured_features()`), and the TF-IDF text input is `subject + " " +
  body_text` from that same parse. None of those functions reference `parsed.headers` (verified by
  inspection — the only caller of `.headers` anywhere in the backend is an unrelated
  Message-ID lookup in `app/api/routes/remediation.py`), so the `X-Aegis-Synthetic*` marker
  headers cannot leak into either the structured or TF-IDF feature space. Whatever the model
  learns from synthetic rows, it can only be learning from their actual subject/body content and
  structure — the same surface a real attack email would present — not a header tell.
- **Diversity**: each generation batch is seeded with a distinct scenario/technique and one of 14
  small-organization "flavors" (e.g. church, school, local nonprofit) to avoid one dominant
  template; a spot-check of the generated 180 samples found 55/32/26 distinct sender domains
  across the credential-phishing/BEC/AI-lure categories respectively (out of 60 each).
- **Cost control**: synthesis is a separate, explicit `python -m aegis_ml.cli synthesize` command,
  deliberately *not* part of `build`'s download step — it spends real Anthropic API tokens, so a
  routine corpus rebuild never silently re-spends them. `build` always picks up whatever synthetic
  files already exist on disk.

## Sources investigated and NOT used

Following the same standard already applied to threat-intel feeds in
`backend/app/threat_intel/data/sources.md` ("Feeds investigated and NOT used"): candidates below
were found during this pass and deliberately excluded, with the specific reason recorded rather
than silently dropped.

- **`zefang-liu/phishing-email-dataset` (Hugging Face)** — REJECTED. Licensed LGPL-3.0, which is
  ambiguous for training data that gets embedded into a shipped product's model artifact (LGPL's
  "linking" exception is written for software libraries, not training corpora baked into a binary
  classifier) — the same conservative standard used to drop commercial-forbidden threat-intel
  feeds. Not used without clearer reuse terms.
- **`darkknight25/phishing_benign_email_dataset` (Hugging Face)** — REJECTED. License (MIT) is
  not the blocker here; the provenance/content inspected looked curated-or-possibly-synthetic
  rather than organically real email, and this project's synthetic rows are already clearly
  labeled as such (see above) — silently absorbing someone else's unlabeled synthetic-or-curated
  data as if it were real would be dishonest about what the corpus actually contains.
- **A standalone real public BEC (Business Email Compromise) corpus** — none found. BEC email is
  inherently sensitive, targeted, and rarely publicly released even in de-identified form (unlike
  bulk commodity phishing or spam, which has decades of public corpora). This is an honest gap:
  the `synthetic_bec` category above is this corpus's *only* source of BEC-pattern training
  examples. Worth revisiting if a licensing-clean real BEC source ever surfaces.

## Design rules for downstream stages
- **`label` is binary** (`phishing` | `benign`) — that's the ground truth these public corpora
  actually provide. There's no public source for a `suspicious` middle class; mapping to Aegis's
  runtime three-way verdict is a later M3 concern, not corpus assembly.
- **No feature fitting before the split.** `split.py` only ever touches deduped raw text/schema
  fields — no vectorizer, no corpus-wide statistic. Whatever fits features in a later M3 stage must
  fit on the `train` split only, to avoid leakage into `val`/`test`.

## Schema addendum: `raw_bytes`

`EmailRecord` also carries the original per-message bytes (`raw_bytes`) alongside the
already-normalized `subject`/`body_text`/`raw_headers` fields — added specifically so that the
feature-extraction stage (`ml/aegis_ml/features.py`) can re-parse each record through the real
backend parser/indicator engine (`app.parsing.eml_parser`, `app.indicators.engine`) rather than
recomputing indicator-relevant fields from this package's own lighter-weight reconstruction. For
mbox sources this is a faithful re-serialization (`email.message.Message.as_bytes()`), not
byte-identical to the original mbox slice; for single-file sources (SpamAssassin, Enron) it is the
true original bytes read straight off disk. Doesn't change provenance/licensing above.
