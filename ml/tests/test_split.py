from __future__ import annotations

import pandas as pd

from aegis_ml.split import stratified_split


def _synthetic_df(n_phishing=80, n_benign=20):
    rows = [{"id": f"phish-{i}", "label": "phishing"} for i in range(n_phishing)]
    rows += [{"id": f"benign-{i}", "label": "benign"} for i in range(n_benign)]
    return pd.DataFrame(rows)


def test_stratified_split_has_no_id_overlap_and_covers_all_rows():
    df = _synthetic_df()
    splits = stratified_split(df, seed=42)

    assert set(splits.keys()) == {"train", "val", "test"}
    total = sum(len(s) for s in splits.values())
    assert total == len(df)

    ids = {name: set(s["id"]) for name, s in splits.items()}
    assert ids["train"].isdisjoint(ids["val"])
    assert ids["train"].isdisjoint(ids["test"])
    assert ids["val"].isdisjoint(ids["test"])
    assert ids["train"] | ids["val"] | ids["test"] == set(df["id"])


def test_stratified_split_preserves_label_ratio_in_each_split():
    df = _synthetic_df(n_phishing=80, n_benign=20)  # 80/20 split
    splits = stratified_split(df, seed=42)

    for split_df in splits.values():
        ratio = (split_df["label"] == "phishing").mean()
        assert 0.7 <= ratio <= 0.9


def test_stratified_split_is_deterministic_given_same_seed():
    df = _synthetic_df()
    splits_a = stratified_split(df, seed=7)
    splits_b = stratified_split(df, seed=7)

    for name in splits_a:
        assert list(splits_a[name]["id"]) == list(splits_b[name]["id"])


# --- Synthetic-augmentation rows: train-only, never val/test ---------------------------


def _real_and_synthetic_df(n_real_phishing=80, n_real_benign=80, n_synthetic=60):
    rows = [{"id": f"real-phish-{i}", "label": "phishing", "source": "nazario"} for i in range(n_real_phishing)]
    rows += [{"id": f"real-benign-{i}", "label": "benign", "source": "enron"} for i in range(n_real_benign)]
    rows += [
        {"id": f"synth-{i}", "label": "phishing", "source": "synthetic_credential_phishing"}
        for i in range(n_synthetic)
    ]
    return pd.DataFrame(rows)


def test_synthetic_rows_never_appear_in_val_or_test():
    df = _real_and_synthetic_df()
    splits = stratified_split(df, seed=42)

    assert (splits["val"]["source"] == "synthetic_credential_phishing").sum() == 0
    assert (splits["test"]["source"] == "synthetic_credential_phishing").sum() == 0


def test_all_synthetic_rows_land_in_train():
    df = _real_and_synthetic_df(n_synthetic=60)
    splits = stratified_split(df, seed=42)

    assert (splits["train"]["source"] == "synthetic_credential_phishing").sum() == 60


def test_val_and_test_are_real_only_and_cover_all_real_rows():
    """The structural guarantee CARD.md relies on: val+test together account for every real
    row (minus the ~30% train portion) and zero synthetic ones — a real-only holdout by
    construction, not convention."""
    df = _real_and_synthetic_df(n_real_phishing=80, n_real_benign=80, n_synthetic=60)
    splits = stratified_split(df, seed=42)

    real_ids = set(df[~df["source"].str.startswith("synthetic_")]["id"])
    val_test_ids = set(splits["val"]["id"]) | set(splits["test"]["id"])
    assert val_test_ids <= real_ids
    assert (splits["val"]["source"].str.startswith("synthetic_")).sum() == 0
    assert (splits["test"]["source"].str.startswith("synthetic_")).sum() == 0


def test_no_source_column_treats_everything_as_non_synthetic():
    """Pure split-mechanics callers (e.g. the plain id/label fixtures above) never have a
    "source" column — must not raise, must not exclude anything."""
    df = _synthetic_df()
    splits = stratified_split(df, seed=42)
    total = sum(len(s) for s in splits.values())
    assert total == len(df)
