"""Pure helpers (queries.py): no server, no Elasticsearch."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import get_args

import pytest
from mcp.server.fastmcp.exceptions import ToolError

import queries

NOW = datetime(2026, 10, 7, 3, 0, 0, tzinfo=UTC)
T0 = datetime(2026, 10, 5, 8, 0, 0, tzinfo=UTC)


# ----------------------------------------------------------------------------- time
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-05T08:30:00Z", datetime(2026, 10, 5, 8, 30, tzinfo=UTC)),
        ("2026-10-05T15:30:00+07:00", datetime(2026, 10, 5, 8, 30, tzinfo=UTC)),
        ("2026-10-05T08:30:00", datetime(2026, 10, 5, 8, 30, tzinfo=UTC)),  # naive ⇒ UTC
        ("2026-10-05", datetime(2026, 10, 5, tzinfo=UTC)),
        ("now", NOW),
        ("now-30m", datetime(2026, 10, 7, 2, 30, tzinfo=UTC)),
        ("NOW-6H", datetime(2026, 10, 6, 21, 0, tzinfo=UTC)),
        ("now-2d", datetime(2026, 10, 5, 3, 0, tzinfo=UTC)),
        ("now-1w", datetime(2026, 9, 30, 3, 0, tzinfo=UTC)),
        ("  now-90s ", datetime(2026, 10, 7, 2, 58, 30, tzinfo=UTC)),
    ],
)
def test_parse_time(value, expected):
    assert queries.parse_time(value, NOW) == expected


@pytest.mark.parametrize(
    "value", ["yesterday", "now+1h", "now-h", "now-5x", "2026-13-45", "", "1759653600", "now - 1h"]
)
def test_parse_time_rejects_garbage(value):
    with pytest.raises(ToolError, match="Invalid time"):
        queries.parse_time(value, NOW)


def test_resolve_window_requires_start_before_end():
    s, e = queries.resolve_window("now-1h", "now", NOW)
    assert (s, e) == (datetime(2026, 10, 7, 2, 0, tzinfo=UTC), NOW)
    for start, end in [("now", "now-1h"), ("now", "now")]:
        with pytest.raises(ToolError, match="before"):
            queries.resolve_window(start, end, NOW)


def test_fmt_ts_handles_epoch_millis_and_iso_strings():
    assert queries.fmt_ts(1791187200000) == "2026-10-05T08:00:00Z"
    assert queries.fmt_ts("2026-10-07T02:33:37+00:00") == "2026-10-07T02:33:37Z"
    assert queries.fmt_ts("2026-10-05T08:00:00.000Z") == "2026-10-05T08:00:00Z"
    assert queries.fmt_ts(None) is None
    assert queries.fmt_ts("not a date") == "not a date"


# ----------------------------------------------------------------------------- bucket size
@pytest.mark.parametrize(
    ("hours", "expected"),
    [(0.25, "1m"), (1, "1m"), (2, "5m"), (6, "10m"), (24, "30m"), (48, "1h"), (24 * 7, "3h")],
)
def test_auto_interval_keeps_points_near_target(hours, expected):
    end = datetime(2026, 10, 7, tzinfo=UTC)
    start = end - timedelta(hours=hours)
    assert queries.pick_interval("auto", start, end) == expected


def test_explicit_interval_is_capped():
    end = datetime(2026, 10, 7, tzinfo=UTC)
    assert queries.pick_interval("5m", end - timedelta(hours=6), end) == "5m"
    with pytest.raises(ToolError, match="larger interval"):
        queries.pick_interval("1m", end - timedelta(days=2), end)


def test_interval_values_match_what_elasticsearch_accepts():
    assert set(get_args(queries.Interval)) == {"auto", *queries._INTERVAL_SECONDS}


# ----------------------------------------------------------------------------- query bodies
def test_metric_vocabulary_is_consistent():
    assert set(get_args(queries.MetricName)) == set(queries.METRICS)


def test_logs_query_filters_and_text():
    dsl = queries.logs_query(
        T0,
        NOW,
        query="No space left",
        host="db-01",
        service="postgres",
        levels=["ERROR"],
    )
    filters = dsl["bool"]["filter"]
    assert filters[0]["range"]["@timestamp"] == {
        "gte": "2026-10-05T08:00:00Z",
        "lte": "2026-10-07T03:00:00Z",
        "format": "strict_date_optional_time",
    }
    assert {"term": {"host.name": "db-01"}} in filters
    assert {"term": {"service.name": "postgres"}} in filters
    assert {"terms": {"log.level": ["ERROR"]}} in filters
    sqs = dsl["bool"]["must"][0]["simple_query_string"]
    assert (sqs["query"], sqs["fields"], sqs["default_operator"]) == (
        "No space left",
        ["message"],
        "and",
    )


def test_logs_query_without_optional_filters_only_has_the_time_range():
    dsl = queries.logs_query(T0, NOW)
    assert len(dsl["bool"]["filter"]) == 1 and "must" not in dsl["bool"]


def test_search_body_never_selects_incident_id():
    body = queries.logs_search_body(queries.logs_query(T0, NOW), order="asc", limit=10, offset=20)
    assert (body["size"], body["from"]) == (10, 20)
    assert body["sort"][0] == {"@timestamp": {"order": "asc"}}
    assert "incident_id" in body["_source"]["excludes"]
    assert "incident_id" not in body["_source"]["includes"]


def test_metric_bodies_only_use_allow_listed_fields():
    body = queries.metric_series_body("web-01", ["cpu_usage_pct", "load_1m"], "max", T0, NOW, "5m")
    aggs = body["aggs"]["series"]["aggs"]
    assert aggs == {
        "cpu_usage_pct": {"max": {"field": "system.cpu.usage_pct"}},
        "load_1m": {"max": {"field": "system.cpu.load_1m"}},
    }
    summary = queries.metrics_summary_body(T0, NOW, None, list(queries.METRICS))
    fields = json.dumps(summary)
    assert "incident_id" not in fields
    assert "cpu_usage_pct__stats" in summary["aggs"]["hosts"]["aggs"]


# ----------------------------------------------------------------------------- parsing
def test_parse_log_hit_ignores_unknown_fields_and_clips_long_messages():
    hit = {
        "_source": {
            "@timestamp": "2026-10-05T08:36:37+00:00",
            "host": {"name": "web-01", "ip": "10.0.1.11"},
            "log": {"level": "ERROR"},
            "service": {"name": "nginx"},
            "message": "x" * 5000,
            "incident_id": "web-01-cpu_spike-360",
        }
    }
    out = queries.parse_log_hit(hit)
    assert "incident_id" not in out and "ip" not in out
    assert out["timestamp"] == "2026-10-05T08:36:37Z"
    assert len(out["message"]) < 1100 and out["message"].endswith("[truncated]")


def test_parse_helpers_tolerate_empty_aggregations():
    assert queries.parse_counts(None) == {}
    assert queries.parse_timeline({}) == []
    assert queries.parse_series({}, ["cpu_usage_pct"]) == []
    assert queries.parse_summary({}, ["cpu_usage_pct"]) == []
    assert queries.parse_hosts({}) == {}
    assert queries.parse_source({}) == {
        "documents": 0,
        "first_timestamp": None,
        "last_timestamp": None,
    }
