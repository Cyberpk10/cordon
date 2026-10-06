"""Downloads the benign ("ham") subset of the Apache SpamAssassin public corpus.

Verified live 2026-08-07 at https://spamassassin.apache.org/old/publiccorpus/ — file listing
scraped directly. Only the ham archives are fetched; the spam ones aren't needed here (and
are never relabeled into the phishing class — generic unsolicited spam, e.g. bulk
advertising, is not the same thing as phishing, and mislabeling it would be a quality
regression, not an improvement).

Re-verified live 2026-10-06: the same index page also lists `20021010_easy_ham.tar.bz2` and
`20021010_hard_ham.tar.bz2` — an earlier (2002-10-10) snapshot from the same corpus,
maintainer, host, and documented terms as the 20030228 archives already in use. Added below
for more benign diversity at zero new licensing-research cost (same already-cleared terms).
`20021010_spam.tar.bz2` on the same page is spam, not ham, and is not used for the same
reason the other spam archives aren't.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import requests

from aegis_ml.paths import RAW_SPAMASSASSIN_DIR, ensure_dirs

BASE_URL = "https://spamassassin.apache.org/old/publiccorpus/"
HAM_ARCHIVES = [
    "20030228_easy_ham.tar.bz2",
    "20030228_hard_ham.tar.bz2",
    "20030228_easy_ham_2.tar.bz2",
    "20021010_easy_ham.tar.bz2",
    "20021010_hard_ham.tar.bz2",
]

USER_AGENT = "aegis-ml-corpus-builder/0.1 (defensive-security research; contact via GitHub)"


def download_spamassassin_ham() -> list[Path]:
    """Downloads + extracts each ham archive (skipping ones already extracted). Returns
    the list of extracted folder paths, e.g. RAW_SPAMASSASSIN_DIR/20030228/easy_ham.

    Each archive's internal top-level folder name is just the category (e.g. `easy_ham/`),
    not date-qualified — two different snapshot dates both ship an `easy_ham/` archive whose
    *contents* extract to that same bare name. Extracting both straight into
    RAW_SPAMASSASSIN_DIR would silently collide: the second archive's extraction would land
    in the same `easy_ham/` directory the first one already populated, and the
    already-extracted guard below would then skip it entirely as "already downloaded" even
    though it never actually ran. Extracting each archive into its own
    RAW_SPAMASSASSIN_DIR/<snapshot-date>/ subdirectory keeps every snapshot's files distinct
    on disk regardless of which dates happen to share a category name.
    """
    ensure_dirs()
    folders: list[Path] = []

    for archive_name in HAM_ARCHIVES:
        date_prefix, category = archive_name.removesuffix(".tar.bz2").split("_", 1)
        dest_root = RAW_SPAMASSASSIN_DIR / date_prefix
        dest_folder = dest_root / category
        if dest_folder.exists() and any(dest_folder.iterdir()):
            folders.append(dest_folder)
            continue

        resp = requests.get(
            BASE_URL + archive_name, timeout=60, headers={"User-Agent": USER_AGENT}
        )
        resp.raise_for_status()

        dest_root.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:bz2") as tar:
            tar.extractall(dest_root, filter="data")

        folders.append(dest_folder)

    return folders
