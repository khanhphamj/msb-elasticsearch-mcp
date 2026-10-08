"""Tool tests (fake Elasticsearch via httpx.MockTransport). Minimum per tool:
happy path + request actually sent · input validation · missing scope · upstream failures · annotations.
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import UTC, datetime

import httpx
import pytest
from conftest import JWT_ENV, call, es_handler, list_tools, make_token, text

from backend import Backend

START, END = "2026-10-05T08:00:00Z", "2026-10-05T09:00:00Z"


def _ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def _sre(scope: str = "logs.read metrics.read") -> str:
    return make_token("sre-agent", scope=scope)


# ----------------------------------------------------------------------------- canned Elasticsearch answers
LOGS_RESPONSE = {
    "took": 4,
    "hits": {
        "total": {"value": 3, "relation": "eq"},
        "hits": [
            {
                "_source": {
                    "@timestamp": "2026-10-05T08:57:37+00:00",
                    "host": {"name": "web-01", "ip": "10.0.1.11", "role": "web"},
                    "log": {"level": "ERROR", "logger": "nginx"},
                    "event": {"dataset": "web", "category": "performance", "outcome": "failure"},
                    "service": {"name": "nginx"},
                    "message": "upstream timed out (110: Connection timed out)",
                    "incident_id": "web-01-cpu_spike-360",  # must never reach the LLM
                }
            },
            {
                "_source": {
                    "@timestamp": "2026-10-05T08:55:37+00:00",
                    "host": {"name": "web-01"},
                    "log": {"level": "WARN"},
                    "service": {"name": "kernel"},
                    "message": "CPU soft lockup suspected on CPU#1",
                }
            },
        ],
    },
}

STATS_RESPONSE = {
    "hits": {"total": {"value": 5, "relation": "eq"}, "hits": []},
    "aggregations": {
        "by_level": {
            "buckets": [{"key": "ERROR", "doc_count": 3}, {"key": "WARN", "doc_count": 2}]
        },
        "by_service": {
            "buckets": [{"key": "nginx", "doc_count": 3}, {"key": "kernel", "doc_count": 2}]
        },
        "by_host": {"buckets": [{"key": "web-01", "doc_count": 5}]},
        "timeline": {
            "buckets": [
                {
                    "key": _ms("2026-10-05T08:36:00Z"),
                    "doc_count": 2,
                    "by_level": {"buckets": [{"key": "WARN", "doc_count": 2}]},
                },
                {
                    "key": _ms("2026-10-05T08:37:00Z"),
                    "doc_count": 3,
                    "by_level": {"buckets": [{"key": "ERROR", "doc_count": 3}]},
                },
            ]
        },
    },
}

SERIES_RESPONSE = {
    "hits": {"total": {"value": 120, "relation": "eq"}, "hits": []},
    "aggregations": {
        "series": {
            "buckets": [
                {
                    "key": _ms("2026-10-05T08:00:00Z"),
                    "doc_count": 5,
                    "cpu_usage_pct": {"value": 12.3456},
                    "load_1m": {"value": None},
                },
                {
                    "key": _ms("2026-10-05T08:05:00Z"),
                    "doc_count": 5,
                    "cpu_usage_pct": {"value": 91.0},
                    "load_1m": {"value": 3.5},
                },
            ]
        }
    },
}

SUMMARY_RESPONSE = {
    "hits": {"total": {"value": 60, "relation": "eq"}, "hits": []},
    "aggregations": {
        "hosts": {
            "buckets": [
                {
                    "key": "web-01",
                    "doc_count": 60,
                    "role": {"buckets": [{"key": "web"}]},
                    "first": {"value": _ms("2026-10-05T08:00:00Z")},
                    "last": {"value": _ms("2026-10-05T08:59:00Z")},
                    "latest": {
                        "hits": {"hits": [{"_source": {"system": {"cpu": {"usage_pct": 12.3}}}}]}
                    },
                    "cpu_usage_pct__stats": {"count": 60, "min": 8.4, "max": 90.54, "avg": 20.1234},
                    "cpu_usage_pct__p95": {"values": {"95.0": 60.0}},
                    "cpu_usage_pct__peak": {
                        "hits": {"hits": [{"_source": {"@timestamp": "2026-10-05T08:41:37+00:00"}}]}
                    },
                }
            ]
        }
    },
}


def _overview_reply(path: str, body: dict) -> dict:
    hosts = {
        "buckets": [
            {
                "key": "db-01",
                "doc_count": 10,
                "role": {"buckets": [{"key": "database"}]},
                "ip": {"buckets": [{"key": "10.0.1.21"}]},
            },
            {
                "key": "web-01",
                "doc_count": 10,
                "role": {"buckets": [{"key": "web"}]},
                "ip": {"buckets": [{"key": "10.0.1.11"}]},
            },
        ]
    }
    first = {"value": _ms("2026-10-05T02:35:37Z")}
    last = {"value": _ms("2026-10-07T02:33:37Z")}
    if path.startswith("/logs-sample"):
        return {
            "hits": {"total": {"value": 2290, "relation": "eq"}, "hits": []},
            "aggregations": {
                "first": first,
                "last": last,
                "hosts": hosts,
                "services": {"buckets": [{"key": "nginx"}, {"key": "postgres"}]},
                "levels": {"buckets": [{"key": "INFO"}, {"key": "ERROR"}]},
            },
        }
    return {
        "hits": {"total": {"value": 5760, "relation": "eq"}, "hits": []},
        "aggregations": {"first": first, "last": last, "hosts": hosts},
    }


# ----------------------------------------------------------------------------- search_logs
async def test_search_logs_sends_the_right_query_and_hides_incident_id(start_server):
    handler, calls = es_handler(lambda path, body: LOGS_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(
        base,
        _sre(),
        "search_logs",
        {
            "start": START,
            "end": END,
            "host": "web-01",
            "service": "nginx",
            "levels": ["ERROR", "WARN"],
            "query": "timed out",
            "limit": 2,
        },
    )
    assert not res.isError
    out = res.structuredContent
    assert (out["start"], out["end"], out["total"], out["next_offset"]) == (START, END, 3, 2)
    assert [i["level"] for i in out["items"]] == ["ERROR", "WARN"]
    assert out["items"][0] == {
        "timestamp": "2026-10-05T08:57:37Z",
        "host": "web-01",
        "level": "ERROR",
        "service": "nginx",
        "dataset": "web",
        "category": "performance",
        "outcome": "failure",
        "message": "upstream timed out (110: Connection timed out)",
    }
    assert "incident_id" not in json.dumps(out) and "cpu_spike" not in json.dumps(out)

    (sent,) = calls
    assert sent["path"] == "/logs-sample/_search"
    body = sent["body"]
    assert (body["size"], body["from"]) == (2, 0)
    filters = body["query"]["bool"]["filter"]
    assert filters[0]["range"]["@timestamp"]["gte"] == START
    assert filters[0]["range"]["@timestamp"]["lte"] == END
    assert {"term": {"host.name": "web-01"}} in filters
    assert {"term": {"service.name": "nginx"}} in filters
    assert {"terms": {"log.level": ["ERROR", "WARN"]}} in filters
    assert body["query"]["bool"]["must"][0]["simple_query_string"]["query"] == "timed out"
    assert "incident_id" in body["_source"]["excludes"]  # defence in depth: not even selected


async def test_search_logs_paginates(start_server):
    handler, _ = es_handler(lambda path, body: LOGS_RESPONSE)  # 2 hits, total 3
    base = start_server(JWT_ENV, backend=handler)
    first = await call(base, _sre(), "search_logs", {"start": START, "end": END})
    assert first.structuredContent["next_offset"] == 2
    last = await call(base, _sre(), "search_logs", {"start": START, "end": END, "offset": 1})
    assert last.structuredContent["next_offset"] is None  # 1 + 2 hits reaches total 3


@pytest.mark.parametrize(
    "args",
    [
        {"start": "yesterday"},
        {"start": "now", "end": "now-1h"},
        {"start": START, "end": END, "host": "web-01; DROP"},
        {"start": START, "end": END, "service": "../etc"},
        {"start": START, "end": END, "levels": ["FATAL"]},
        {"start": START, "end": END, "limit": 101},
        {"start": START, "end": END, "limit": 0},
        {"start": START, "end": END, "offset": 9901},
        {"start": START, "end": END, "order": "sideways"},
        {"start": START, "end": END, "query": "x" * 201},
        {"end": END},  # start is required
    ],
    ids=[
        "bad-time",
        "start-after-end",
        "host-injection",
        "service-path",
        "unknown-level",
        "limit-too-big",
        "limit-zero",
        "offset-too-big",
        "bad-order",
        "query-too-long",
        "missing-start",
    ],
)
async def test_search_logs_rejects_bad_input_before_touching_elasticsearch(start_server, args):
    handler, calls = es_handler(lambda path, body: LOGS_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(base, _sre(), "search_logs", args)
    assert res.isError
    assert calls == []


async def test_relative_times_use_the_server_clock(start_server, monkeypatch):
    handler, calls = es_handler(lambda path, body: LOGS_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    monkeypatch.setattr(
        sys.modules["server"], "_now", lambda: datetime(2026, 10, 7, 3, 0, tzinfo=UTC)
    )
    res = await call(base, _sre(), "search_logs", {"start": "now-6h"})
    assert (res.structuredContent["start"], res.structuredContent["end"]) == (
        "2026-10-06T21:00:00Z",
        "2026-10-07T03:00:00Z",
    )
    assert calls[0]["body"]["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] == (
        "2026-10-06T21:00:00Z"
    )


# ----------------------------------------------------------------------------- scopes, upstream failures
async def test_tools_require_their_scope(start_server):
    handler, calls = es_handler(lambda path, body: LOGS_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    only_metrics, only_logs = _sre("metrics.read"), _sre("logs.read")
    cases = [
        (only_metrics, "search_logs", {"start": START, "end": END}, "logs.read"),
        (only_metrics, "get_log_stats", {"start": START, "end": END}, "logs.read"),
        (only_logs, "get_metrics_summary", {"start": START, "end": END}, "metrics.read"),
        (
            only_logs,
            "get_metrics",
            {"host": "web-01", "metrics": ["cpu_usage_pct"], "start": START, "end": END},
            "metrics.read",
        ),
        (only_logs, "get_overview", {}, "metrics.read"),  # reads both indices
    ]
    for token, tool, args, scope in cases:
        res = await call(base, token, tool, args)
        assert res.isError and scope in text(res), tool
    assert calls == []


UPSTREAM_FAILURES = [
    (httpx.Response(500, text="Traceback ... password=hunter2 @ backend.test"), "error (500)"),
    (httpx.Response(503, text="backend.test is down"), "error (503)"),
    (httpx.Response(401, text="bad credentials hunter2"), "not allowed"),
    (httpx.Response(403, text="forbidden for backend.test"), "not allowed"),
    (httpx.Response(404, json={"error": {"type": "index_not_found_exception"}}), "not found"),
    (httpx.Response(400, json={"error": {"type": "search_phase_execution_exception"}}), "rejected"),
    (httpx.Response(429, text="slow down"), "overloaded"),
    (httpx.Response(200, text="<html>hunter2 backend.test</html>"), "unexpected response"),
    (httpx.Response(200, json=["not", "an", "object"]), "unexpected response"),
]


@pytest.mark.parametrize(("reply", "expected"), UPSTREAM_FAILURES)
async def test_upstream_failures_are_clean(start_server, reply, expected):
    handler, _ = es_handler(lambda path, body: reply)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(base, _sre(), "search_logs", {"start": START, "end": END})
    assert res.isError and expected in text(res).lower()
    assert "hunter2" not in text(res) and "backend.test" not in text(res)  # no leaks


async def test_upstream_timeout_and_unreachable_are_clean(start_server):
    def slow(path, body):
        raise httpx.ReadTimeout("slow")

    def down(path, body):
        raise httpx.ConnectError("connection refused to backend.test:9200")

    for reply, expected in ((slow, "timed out"), (down, "unreachable")):
        handler, _ = es_handler(reply)
        base = start_server(JWT_ENV, backend=handler)
        res = await call(base, _sre(), "get_metrics_summary", {"start": START, "end": END})
        assert res.isError and expected in text(res).lower()
        assert "backend.test" not in text(res) and "9200" not in text(res)


async def test_unexpected_response_shape_is_clean(start_server):
    broken = {"hits": {"total": {"value": 1}, "hits": [{"_source": {"message": "no host/level"}}]}}
    handler, _ = es_handler(lambda path, body: broken)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(base, _sre(), "search_logs", {"start": START, "end": END})
    assert res.isError and "unexpected response" in text(res).lower()
    assert "ValidationError" not in text(res) and "pydantic" not in text(res).lower()


async def test_not_configured_locally(local_server):
    for tool, args in (
        ("get_overview", {}),
        ("search_logs", {"start": START, "end": END}),
        ("get_metrics_summary", {"start": START, "end": END}),
    ):
        res = await call(local_server, None, tool, args)
        assert res.isError and "MCP_BACKEND_URL" in text(res), tool


# ----------------------------------------------------------------------------- get_log_stats
async def test_get_log_stats(start_server):
    handler, calls = es_handler(lambda path, body: STATS_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(
        base, _sre(), "get_log_stats", {"start": START, "end": END, "levels": ["WARN", "ERROR"]}
    )
    assert not res.isError
    out = res.structuredContent
    assert out["interval"] == "1m"  # 1 h window ⇒ ≤ 60 buckets
    assert (out["total"], out["by_level"], out["by_host"]) == (
        5,
        {"ERROR": 3, "WARN": 2},
        {"web-01": 5},
    )
    assert out["timeline"] == [
        {"timestamp": "2026-10-05T08:36:00Z", "count": 2, "by_level": {"WARN": 2}},
        {"timestamp": "2026-10-05T08:37:00Z", "count": 3, "by_level": {"ERROR": 3}},
    ]
    sent = calls[0]
    assert sent["path"] == "/logs-sample/_search" and sent["body"]["size"] == 0
    assert sent["body"]["aggs"]["timeline"]["date_histogram"]["fixed_interval"] == "1m"


async def test_get_log_stats_interval_is_capped(start_server):
    handler, calls = es_handler(lambda path, body: STATS_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(
        base,
        _sre(),
        "get_log_stats",
        {"start": "2026-10-05T00:00:00Z", "end": "2026-10-07T00:00:00Z", "interval": "1m"},
    )
    assert res.isError and "larger interval" in text(res)
    assert calls == []


# ----------------------------------------------------------------------------- get_metrics
async def test_get_metrics_series(start_server):
    handler, calls = es_handler(lambda path, body: SERIES_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(
        base,
        _sre(),
        "get_metrics",
        {
            "host": "web-01",
            "metrics": ["cpu_usage_pct", "load_1m", "cpu_usage_pct"],  # duplicate is dropped
            "start": START,
            "end": END,
            "interval": "5m",
        },
    )
    assert not res.isError
    out = res.structuredContent
    assert (out["host"], out["interval"], out["agg"]) == ("web-01", "5m", "max")
    assert out["units"] == {"cpu_usage_pct": "%", "load_1m": "load avg"}
    assert out["points"] == [
        {"timestamp": "2026-10-05T08:00:00Z", "values": {"cpu_usage_pct": 12.35, "load_1m": None}},
        {"timestamp": "2026-10-05T08:05:00Z", "values": {"cpu_usage_pct": 91.0, "load_1m": 3.5}},
    ]
    assert out["note"] is None

    (sent,) = calls
    assert sent["path"] == "/metrics-sample/_search"
    assert {"term": {"host.name": "web-01"}} in sent["body"]["query"]["bool"]["filter"]
    assert sent["body"]["aggs"]["series"]["aggs"] == {
        "cpu_usage_pct": {"max": {"field": "system.cpu.usage_pct"}},
        "load_1m": {"max": {"field": "system.cpu.load_1m"}},
    }


async def test_get_metrics_avg_and_empty_result_note(start_server):
    empty = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {"series": {"buckets": []}},
    }
    handler, calls = es_handler(lambda path, body: empty)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(
        base,
        _sre(),
        "get_metrics",
        {"host": "nope-99", "metrics": ["load_5m"], "start": START, "end": END, "agg": "avg"},
    )
    assert not res.isError and res.structuredContent["points"] == []
    assert "No samples" in res.structuredContent["note"]
    assert calls[0]["body"]["aggs"]["series"]["aggs"]["load_5m"] == {
        "avg": {"field": "system.cpu.load_5m"}
    }


@pytest.mark.parametrize(
    "args",
    [
        {"host": "web-01", "metrics": ["cpu_usage_pct; DROP"], "start": START, "end": END},
        {"host": "web-01", "metrics": ["system.cpu.usage_pct"], "start": START, "end": END},
        {"host": "web-01", "metrics": [], "start": START, "end": END},
        {"host": "web-01", "metrics": ["cpu_usage_pct"] * 7, "start": START, "end": END},
        {"host": "web 01", "metrics": ["cpu_usage_pct"], "start": START, "end": END},
        {"host": "web-01", "metrics": ["cpu_usage_pct"], "start": START, "end": END, "agg": "sum"},
        {"metrics": ["cpu_usage_pct"], "start": START, "end": END},  # host is required
    ],
    ids=["injection", "raw-es-field", "no-metrics", "too-many", "bad-host", "bad-agg", "no-host"],
)
async def test_get_metrics_rejects_bad_input(start_server, args):
    handler, calls = es_handler(lambda path, body: SERIES_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(base, _sre(), "get_metrics", args)
    assert res.isError and calls == []


# ----------------------------------------------------------------------------- get_metrics_summary
async def test_get_metrics_summary(start_server):
    handler, calls = es_handler(lambda path, body: SUMMARY_RESPONSE)
    base = start_server(JWT_ENV, backend=handler)
    res = await call(
        base,
        _sre(),
        "get_metrics_summary",
        {"start": START, "end": END, "host": "web-01", "metrics": ["cpu_usage_pct"]},
    )
    assert not res.isError
    (host,) = res.structuredContent["hosts"]
    assert (host["host"], host["role"], host["samples"]) == ("web-01", "web", 60)
    assert (host["first_sample"], host["last_sample"]) == (
        "2026-10-05T08:00:00Z",
        "2026-10-05T08:59:00Z",
    )
    assert host["metrics"] == [
        {
            "metric": "cpu_usage_pct",
            "unit": "%",
            "latest": 12.3,
            "min": 8.4,
            "avg": 20.12,
            "p95": 60.0,
            "max": 90.54,
            "peak_at": "2026-10-05T08:41:37Z",
        }
    ]
    sent = calls[0]
    assert sent["path"] == "/metrics-sample/_search"
    assert {"term": {"host.name": "web-01"}} in sent["body"]["query"]["bool"]["filter"]
    assert "cpu_usage_pct__stats" in sent["body"]["aggs"]["hosts"]["aggs"]
    assert "load_1m__stats" not in sent["body"]["aggs"]["hosts"]["aggs"]  # only what was asked


async def test_get_metrics_summary_defaults_to_all_metrics_and_hosts(start_server):
    handler, calls = es_handler(
        lambda path, body: {"hits": {"total": {"value": 0}}, "aggregations": {}}
    )
    base = start_server(JWT_ENV, backend=handler)
    res = await call(base, _sre(), "get_metrics_summary", {"start": START, "end": END})
    assert not res.isError and res.structuredContent["hosts"] == []
    assert "No samples" in res.structuredContent["note"]
    aggs = calls[0]["body"]["aggs"]["hosts"]["aggs"]
    assert len([k for k in aggs if k.endswith("__stats")]) == 11
    assert len(calls[0]["body"]["query"]["bool"]["filter"]) == 1  # time range only


# ----------------------------------------------------------------------------- get_overview
async def test_get_overview(start_server, monkeypatch):
    handler, calls = es_handler(_overview_reply)
    base = start_server(JWT_ENV, backend=handler)
    monkeypatch.setattr(
        sys.modules["server"], "_now", lambda: datetime(2026, 10, 7, 3, 30, tzinfo=UTC)
    )
    res = await call(base, _sre(), "get_overview")
    assert not res.isError
    out = res.structuredContent
    assert out["server_time"] == "2026-10-07T03:30:00Z"
    assert out["hosts"] == [
        {"name": "db-01", "role": "database", "ip": "10.0.1.21"},
        {"name": "web-01", "role": "web", "ip": "10.0.1.11"},
    ]
    assert out["logs"] == {
        "documents": 2290,
        "first_timestamp": "2026-10-05T02:35:37Z",
        "last_timestamp": "2026-10-07T02:33:37Z",
    }
    assert out["metrics"]["documents"] == 5760
    assert out["log_services"] == ["nginx", "postgres"] and out["log_levels"] == ["INFO", "ERROR"]
    assert "cpu_usage_pct" in out["metric_names"] and len(out["metric_names"]) == 11
    assert sorted(c["path"] for c in calls) == ["/logs-sample/_search", "/metrics-sample/_search"]


# ----------------------------------------------------------------------------- metadata, backend client
async def test_tool_annotations_and_schemas(local_server):
    tools = {t.name: t for t in await list_tools(local_server)}
    assert set(tools) == {
        "get_overview",
        "search_logs",
        "get_log_stats",
        "get_metrics",
        "get_metrics_summary",
    }
    for t in tools.values():
        assert t.annotations.readOnlyHint is True, t.name  # nothing here can change data
        assert t.outputSchema is not None, t.name  # structured output
        assert (t.description or "").strip(), t.name
    # LLM-facing contract: metric names are an enum, not free text
    metric_items = tools["get_metrics"].inputSchema["properties"]["metrics"]["items"]
    assert "cpu_usage_pct" in metric_items["enum"]
    assert "incident_id" not in json.dumps([t.model_dump(mode="json") for t in tools.values()])


async def test_backend_sends_basic_auth_and_targets_the_index():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"hits": {"hits": []}})

    backend = Backend(
        "http://es.test:9200",
        2,
        transport=httpx.MockTransport(handler),
        username="sre_agent",
        password="s3cret",
    )
    await backend.search("logs-sample", {"size": 0})
    (req,) = seen
    expected = "Basic " + base64.b64encode(b"sre_agent:s3cret").decode()
    assert req.headers["authorization"] == expected
    assert (req.method, req.url.path) == ("POST", "/logs-sample/_search")
    assert json.loads(req.content) == {"size": 0}
