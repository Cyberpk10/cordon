"""Offline IP -> country lookup over the bundled DB-IP "IP to Country Lite" snapshot
(app/geo/data/country_ranges.tsv.gz, produced by scripts/refresh_geoip.py; license and
provenance in app/geo/data/sources.md).

Country-level only. City-level IP geolocation is unreliable and isn't offered. No network
calls anywhere in this module, consistent with the rest of analysis being self-contained.

Honesty contract: an IP resolves to a country only when it falls in a range the dataset
assigns a real country code. Everything else is reported as what it is:
  - "non_public": private/loopback/link-local/reserved/documentation space. Not on the
    internet at all, so there is no location to give.
  - "unknown": a public address the dataset has no country for (DB-IP's "ZZ"), an
    unparseable value, or no snapshot loaded. Never a guessed country.
A missing or unreadable snapshot degrades every lookup to "unknown". It never raises, the
same missing-artifact contract as app.threat_intel.loader and app.ml.classifier.
"""

from __future__ import annotations

import gzip
import ipaddress
import logging
from array import array
from bisect import bisect_right
from itertools import accumulate
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

from app.geo.countries import COUNTRY_NAMES

logger = logging.getLogger(__name__)

DATASET_NAME = "DB-IP IP to Country Lite"
DATASET_ATTRIBUTION = "IP geolocation by DB-IP"
DATASET_URL = "https://db-ip.com"

_DEFAULT_PATH = Path(__file__).parent / "data" / "country_ranges.tsv.gz"

GeoStatus = Literal["resolved", "non_public", "unknown"]


@dataclass(frozen=True)
class GeoDataset:
    v4_starts: array  # array('I'), sorted range starts
    v4_codes: array  # array('H'), index into `codes`
    v6_starts: list[int]  # 128-bit ints don't fit an array typecode
    v6_codes: array
    codes: tuple[str, ...]
    snapshot: str | None

    @property
    def is_empty(self) -> bool:
        return not self.v4_starts and not self.v6_starts


@dataclass(frozen=True)
class GeoResult:
    status: GeoStatus
    country_code: str | None = None
    country_name: str | None = None
    snapshot: str | None = None


_EMPTY = GeoDataset(array("I"), array("H"), [], array("H"), (), None)


def load_dataset(path: Path) -> GeoDataset:
    """Parses a snapshot file. Returns an empty dataset (every lookup -> unknown) if the file
    is missing or malformed."""
    if not path.exists():
        return _EMPTY
    try:
        text = gzip.decompress(path.read_bytes()).decode("utf-8")
        snapshot: str | None = None
        fam_rows: dict[str, tuple[list[str], list[str]]] = {"4": ([], []), "6": ([], [])}
        for line in text.splitlines():
            if not line:
                continue
            if line[0] == "#":
                if snapshot is None and "snapshot:" in line:
                    snapshot = line.split("snapshot:", 1)[1].strip()
                continue
            fam, delta, code = line.split("\t")
            deltas, row_codes = fam_rows[fam]
            deltas.append(delta)
            row_codes.append(code)

        codes = tuple(sorted(set(fam_rows["4"][1]) | set(fam_rows["6"][1])))
        code_index = {c: i for i, c in enumerate(codes)}
        v4_starts = array("I", accumulate(map(int, fam_rows["4"][0])))
        v6_starts = list(accumulate(map(int, fam_rows["6"][0])))
        v4_codes = array("H", map(code_index.__getitem__, fam_rows["4"][1]))
        v6_codes = array("H", map(code_index.__getitem__, fam_rows["6"][1]))
        return GeoDataset(v4_starts, v4_codes, v6_starts, v6_codes, codes, snapshot)
    except Exception:  # noqa: BLE001 — a corrupt snapshot must disable geo, not break analysis
        logger.exception("Failed to load geo snapshot %s; all lookups will be 'unknown'", path)
        return _EMPTY


@lru_cache(maxsize=1)
def default_dataset() -> GeoDataset:
    return load_dataset(_DEFAULT_PATH)


def lookup_country(ip: str | None, dataset: GeoDataset | None = None) -> GeoResult:
    if not ip:
        return GeoResult(status="unknown")
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError:
        return GeoResult(status="unknown")
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not addr.is_global:
        return GeoResult(status="non_public")

    ds = dataset if dataset is not None else default_dataset()
    if ds.is_empty:
        return GeoResult(status="unknown")

    if addr.version == 4:
        starts, code_idx = ds.v4_starts, ds.v4_codes
    else:
        starts, code_idx = ds.v6_starts, ds.v6_codes
    pos = bisect_right(starts, int(addr)) - 1
    if pos < 0:
        return GeoResult(status="unknown", snapshot=ds.snapshot)
    code = ds.codes[code_idx[pos]]
    if code == "ZZ" or len(code) != 2:
        return GeoResult(status="unknown", snapshot=ds.snapshot)
    return GeoResult(
        status="resolved",
        country_code=code,
        country_name=COUNTRY_NAMES.get(code, code),
        snapshot=ds.snapshot,
    )
