from __future__ import annotations

import pytest

from app.activity_log.parser import (
    MAX_ROWS,
    ActivityLogParseError,
    parse_activity_log_csv,
)
from app.events.schema import EventAction

VALID_CSV = """timestamp,account,source_ip,geo,result
2026-10-15T02:08:41Z,j.carter@northstar-clinic.org,185.220.101.44,RU,FAIL
2026-10-15T02:14:50Z,admin@northstar-clinic.org,185.220.101.44,RU,SUCCESS
"""


def test_parses_valid_csv_into_activity_events():
    events = parse_activity_log_csv(VALID_CSV)
    assert len(events) == 2
    assert events[0].actor == "j.carter@northstar-clinic.org"
    assert events[0].source_ip == "185.220.101.44"
    assert events[0].geo is not None and events[0].geo.country == "RU"
    assert events[0].action == EventAction.AUTH_FAIL
    assert events[1].action == EventAction.LOGIN
    assert events[1].outcome == "success"


def test_header_is_case_insensitive_and_whitespace_tolerant():
    csv_text = "  TIMESTAMP , Account, SOURCE_ip , geo , Result  \n2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,SUCCESS\n"
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1


def test_blank_lines_and_comment_lines_are_skipped():
    csv_text = (
        "# this is a demo log\n"
        "\n"
        "timestamp,account,source_ip,geo,result\n"
        "\n"
        "# a comment between rows\n"
        "2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,SUCCESS\n"
        "\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1


def test_rows_and_fields_are_whitespace_trimmed():
    csv_text = "timestamp,account,source_ip,geo,result\n  2026-10-15T02:08:41Z , a@x.org , 1.2.3.4 , US , SUCCESS  \n"
    events = parse_activity_log_csv(csv_text)
    assert events[0].actor == "a@x.org"
    assert events[0].source_ip == "1.2.3.4"


def test_result_values_are_case_insensitive():
    csv_text = "timestamp,account,source_ip,geo,result\n2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,success\n"
    events = parse_activity_log_csv(csv_text)
    assert events[0].action == EventAction.LOGIN
    assert events[0].outcome == "success"


def test_unknown_result_value_becomes_a_generic_event_not_a_crash():
    csv_text = "timestamp,account,source_ip,geo,result\n2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,SOMETHING_NEW\n"
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].action == EventAction.CONFIG_CHANGE
    assert events[0].outcome == "something_new"


def test_bulk_download_with_no_bytes_column_has_no_byte_count():
    csv_text = "timestamp,account,source_ip,geo,result\n2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD\n"
    events = parse_activity_log_csv(csv_text)
    assert events[0].action == EventAction.FILE_DOWNLOAD
    assert events[0].bytes is None


def test_six_column_header_with_bytes_is_accepted():
    csv_text = (
        "timestamp,account,source_ip,geo,result,bytes\n"
        "2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD,900000000\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].bytes == 900_000_000


def test_five_column_header_still_works_without_bytes_column():
    csv_text = "timestamp,account,source_ip,geo,result\n2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD\n"
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].bytes is None


def test_mixed_rows_some_with_bytes_some_without():
    csv_text = (
        "timestamp,account,source_ip,geo,result,bytes\n"
        "2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD,123456789\n"
        "2026-10-15T02:09:41Z,b@x.org,1.2.3.4,US,BULK_DOWNLOAD,\n"
        "2026-10-15T02:10:41Z,c@x.org,1.2.3.4,US,SUCCESS,\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 3
    assert events[0].bytes == 123_456_789
    assert events[1].bytes is None
    assert events[2].bytes is None


def test_non_numeric_bytes_is_ignored_gracefully_not_fatal():
    csv_text = (
        "timestamp,account,source_ip,geo,result,bytes\n"
        "2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD,not-a-number\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].bytes is None


def test_negative_bytes_is_ignored_gracefully_not_fatal():
    csv_text = (
        "timestamp,account,source_ip,geo,result,bytes\n"
        "2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD,-5\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].bytes is None


def test_six_column_header_is_case_insensitive_and_whitespace_tolerant():
    csv_text = (
        "  TIMESTAMP , Account, SOURCE_ip , geo , Result , Bytes \n"
        "2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,BULK_DOWNLOAD,42\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].bytes == 42


def test_missing_header_raises_clean_validation_error():
    with pytest.raises(ActivityLogParseError, match="Expected CSV header"):
        parse_activity_log_csv("not,the,right,header,shape\n1,2,3,4,5\n")


def test_wrong_column_order_raises_clean_validation_error():
    with pytest.raises(ActivityLogParseError, match="Expected CSV header"):
        parse_activity_log_csv("account,timestamp,source_ip,geo,result\na@x.org,2026-10-15T02:08:41Z,1.2.3.4,US,SUCCESS\n")


def test_empty_input_raises_clean_validation_error():
    with pytest.raises(ActivityLogParseError):
        parse_activity_log_csv("")


def test_only_whitespace_and_comments_raises_clean_validation_error():
    with pytest.raises(ActivityLogParseError):
        parse_activity_log_csv("   \n# just a comment\n\n")


def test_header_only_with_no_data_rows_raises_clean_validation_error():
    with pytest.raises(ActivityLogParseError, match="No valid rows"):
        parse_activity_log_csv("timestamp,account,source_ip,geo,result\n")


def test_malformed_individual_rows_are_skipped_not_fatal():
    csv_text = (
        "timestamp,account,source_ip,geo,result\n"
        "not-a-timestamp,a@x.org,1.2.3.4,US,SUCCESS\n"
        "2026-10-15T02:08:41Z,,1.2.3.4,US,SUCCESS\n"  # missing account
        "2026-10-15T02:08:41Z,b@x.org,1.2.3.4,US,SUCCESS\n"  # valid
        "too,few,fields\n"
    )
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1
    assert events[0].actor == "b@x.org"


def test_all_rows_malformed_raises_clean_validation_error_not_a_crash():
    csv_text = "timestamp,account,source_ip,geo,result\nnot-a-timestamp,a@x.org,1.2.3.4,US,SUCCESS\n"
    with pytest.raises(ActivityLogParseError, match="No valid rows"):
        parse_activity_log_csv(csv_text)


def test_row_count_over_cap_is_rejected_with_a_clean_error():
    header = "timestamp,account,source_ip,geo,result\n"
    rows = "\n".join(f"2026-10-15T02:08:{i % 60:02d}Z,a@x.org,1.2.3.4,US,SUCCESS" for i in range(MAX_ROWS + 1))
    with pytest.raises(ActivityLogParseError, match="Too many rows"):
        parse_activity_log_csv(header + rows)


def test_row_count_at_cap_is_accepted():
    header = "timestamp,account,source_ip,geo,result\n"
    rows = "\n".join(f"2026-10-15T02:{(i // 60) % 24:02d}:{i % 60:02d}Z,a@x.org,1.2.3.4,US,SUCCESS" for i in range(MAX_ROWS))
    events = parse_activity_log_csv(header + rows)
    assert len(events) == MAX_ROWS


def test_byte_order_mark_is_stripped():
    csv_text = "﻿timestamp,account,source_ip,geo,result\n2026-10-15T02:08:41Z,a@x.org,1.2.3.4,US,SUCCESS\n"
    events = parse_activity_log_csv(csv_text)
    assert len(events) == 1


def test_geo_and_source_ip_are_optional():
    csv_text = "timestamp,account,source_ip,geo,result\n2026-10-15T02:08:41Z,a@x.org,,,SUCCESS\n"
    events = parse_activity_log_csv(csv_text)
    assert events[0].source_ip is None
    assert events[0].geo is None
