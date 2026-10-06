"""Per-source parse -> common schema -> ml/data/interim/<source>.parquet."""

from __future__ import annotations

import pandas as pd

from aegis_ml.download.spamassassin import HAM_ARCHIVES
from aegis_ml.paths import INTERIM_DIR, RAW_ENRON_DIR, RAW_NAZARIO_DIR, RAW_SPAMASSASSIN_DIR, ensure_dirs
from aegis_ml.parsers.maildir_parser import iter_maildir_records
from aegis_ml.parsers.mbox_parser import iter_mbox_records, iter_single_message_dir_records
from aegis_ml.schema import EMAIL_RECORD_COLUMNS, EmailRecord, Label, Source
from aegis_ml.synthesize import CATEGORY_CONFIG, RAW_SYNTHETIC_DIR

# Derived from HAM_ARCHIVES (not hand-duplicated) so this can never silently drift from what
# aegis_ml.download.spamassassin actually extracts — each archive lands at
# RAW_SPAMASSASSIN_DIR/<date>/<category>/ (see that module's download_spamassassin_ham
# docstring for why the date-qualified subdirectory is required, not optional).
SPAMASSASSIN_HAM_SUBDIRS = tuple(
    archive.removesuffix(".tar.bz2").split("_", 1) for archive in HAM_ARCHIVES
)


def _records_to_df(records: list[EmailRecord]) -> pd.DataFrame:
    if not records:
        return pd.DataFrame(columns=EMAIL_RECORD_COLUMNS)
    return pd.DataFrame([r.to_dict() for r in records], columns=EMAIL_RECORD_COLUMNS)


def normalize_nazario() -> pd.DataFrame:
    records: list[EmailRecord] = []
    for mbox_path in sorted(RAW_NAZARIO_DIR.glob("*.mbox")):
        records.extend(iter_mbox_records(mbox_path, source=Source.NAZARIO, label=Label.PHISHING))
    df = _records_to_df(records)
    ensure_dirs()
    df.to_parquet(INTERIM_DIR / "nazario.parquet", index=False)
    return df


def normalize_spamassassin() -> pd.DataFrame:
    records: list[EmailRecord] = []
    for date_prefix, category in SPAMASSASSIN_HAM_SUBDIRS:
        directory = RAW_SPAMASSASSIN_DIR / date_prefix / category
        if directory.exists():
            records.extend(
                iter_single_message_dir_records(
                    directory,
                    source=Source.SPAMASSASSIN,
                    label=Label.BENIGN,
                    id_prefix=f"{date_prefix}/{category}",
                )
            )
    df = _records_to_df(records)
    ensure_dirs()
    df.to_parquet(INTERIM_DIR / "spamassassin.parquet", index=False)
    return df


def normalize_enron() -> pd.DataFrame:
    records: list[EmailRecord] = []
    if RAW_ENRON_DIR.exists():
        records.extend(iter_maildir_records(RAW_ENRON_DIR, source=Source.ENRON, label=Label.BENIGN))
    df = _records_to_df(records)
    ensure_dirs()
    df.to_parquet(INTERIM_DIR / "enron.parquet", index=False)
    return df


def normalize_synthetic() -> pd.DataFrame:
    """Reads whatever aegis_ml.synthesize has already written to disk (never generates
    anything itself — see that module's docstring for why generation is a separate, explicit
    step). Each category directory's Source value is pulled from CATEGORY_CONFIG so this can
    never drift from what the generator actually tags."""
    records: list[EmailRecord] = []
    for category, cfg in CATEGORY_CONFIG.items():
        directory = RAW_SYNTHETIC_DIR / category
        if directory.exists():
            records.extend(
                iter_single_message_dir_records(
                    directory,
                    source=cfg["source"],
                    label=Label.PHISHING,
                    id_prefix=f"synthetic/{category}",
                )
            )
    df = _records_to_df(records)
    ensure_dirs()
    df.to_parquet(INTERIM_DIR / "synthetic.parquet", index=False)
    return df


def normalize_all() -> dict[str, pd.DataFrame]:
    return {
        "nazario": normalize_nazario(),
        "spamassassin": normalize_spamassassin(),
        "enron": normalize_enron(),
        "synthetic": normalize_synthetic(),
    }
