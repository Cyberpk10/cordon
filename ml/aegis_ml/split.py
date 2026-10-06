"""Stratified train/val/test split, run AFTER dedupe and before any feature fitting — no
vectorizer or corpus-wide statistic is computed anywhere in this pipeline. Whatever fits
features in a later M3 stage must fit only on the train split written here.

Synthetic rows (aegis_ml.synthesize — source values starting with "synthetic_") are held out
of the stratification entirely and appended to the train split only, never val or test. This
is the structural mechanism behind two requirements this pipeline cares about, not just a
convention: (1) val/test stay a REAL-only holdout by construction, so "evaluate on a held-out
real test set" and "validate the model isn't learning synthetic tells by testing on a
real-only holdout" (ml/models/CARD.md) are verifiable facts about how the splits were built,
not assertions; (2) a synthetic sample can never be the thing a precision/recall number is
measured against, so augmentation can only ever change what the model learns from, never what
it's graded on.
"""

from __future__ import annotations

import pandas as pd
from sklearn.model_selection import train_test_split

from aegis_ml.paths import PROCESSED_DIR, ensure_dirs

DEFAULT_SEED = 42
TRAIN_FRAC = 0.7
VAL_FRAC = 0.15
TEST_FRAC = 0.15

_SYNTHETIC_SOURCE_PREFIX = "synthetic_"


def _is_synthetic(df: pd.DataFrame) -> pd.Series:
    if "source" not in df.columns:
        # Callers outside the real pipeline (tests exercising pure split mechanics with a
        # minimal id/label-only frame) never have synthetic rows to exclude in the first
        # place — every real caller's DataFrame always has a "source" column (see
        # aegis_ml.schema.EMAIL_RECORD_COLUMNS).
        return pd.Series(False, index=df.index)
    return df["source"].astype(str).str.startswith(_SYNTHETIC_SOURCE_PREFIX)


def stratified_split(df: pd.DataFrame, seed: int = DEFAULT_SEED) -> dict[str, pd.DataFrame]:
    synthetic_mask = _is_synthetic(df)
    synthetic_df = df[synthetic_mask]
    real_df = df[~synthetic_mask]

    train_df, temp_df = train_test_split(
        real_df, test_size=(VAL_FRAC + TEST_FRAC), stratify=real_df["label"], random_state=seed
    )
    val_df, test_df = train_test_split(
        temp_df,
        test_size=TEST_FRAC / (VAL_FRAC + TEST_FRAC),
        stratify=temp_df["label"],
        random_state=seed,
    )

    if len(synthetic_df):
        train_df = pd.concat([train_df, synthetic_df], ignore_index=True)

    return {
        "train": train_df.reset_index(drop=True),
        "val": val_df.reset_index(drop=True),
        "test": test_df.reset_index(drop=True),
    }


def write_splits(splits: dict[str, pd.DataFrame]) -> None:
    ensure_dirs()
    for name, split_df in splits.items():
        split_df.to_parquet(PROCESSED_DIR / f"{name}.parquet", index=False)
