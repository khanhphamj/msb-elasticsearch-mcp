"""Pure helpers behind the tools: time parsing, bucket-size choice, Elasticsearch query bodies and response
parsing. No I/O ⇒ unit-testable without a server (tests/test_queries.py).

What the LLM controls is validated or allow-listed before it reaches Elasticsearch: metric names map to fixed
field names (METRICS), times become absolute UTC instants, free text goes through `simple_query_string`
(it never raises on bad syntax), and the sample data's ground-truth label `incident_id` is excluded from
`_source`, so it can never be returned by any tool.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from mcp.server.fastmcp.exceptions import ToolError

# ----------------------------------------------------------------------------- vocabulary of tool arguments
LogLevel = Literal["DEBUG", "INFO", "WARN", "ERROR"]
Interval = Literal["auto", "1m", "5m", "10m", "15m", "30m", "1h", "3h", "6h", "12h", "1d"]
Agg = Literal["avg", "max", "min"]
MetricName = Literal[
    "cpu_usage_pct",
    "load_1m",
    "load_5m",
    "load_15m",
    "memory_used_pct",
    "memory_used_bytes",
    "disk_used_pct",
    "disk_io_read_bytes_per_s",
    "disk_io_write_bytes_per_s",
    "network_in_bytes_per_s",
    "network_out_bytes_per_s",
]

# Metric name shown to the LLM -> (Elasticsearch field, unit). Allow-list: arguments never become field names.
METRICS: dict[str, tuple[str, str]] = {
    "cpu_usage_pct": ("system.cpu.usage_pct", "%"),
    "load_1m": ("system.cpu.load_1m", "load avg"),
    "load_5m": ("system.cpu.load_5m", "load avg"),
    "load_15m": ("system.cpu.load_15m", "load avg"),
    "memory_used_pct": ("system.memory.used_pct", "%"),
    "memory_used_bytes": ("system.memory.used_bytes", "bytes"),
    "disk_used_pct": ("system.disk.used_pct", "%"),
    "disk_io_read_bytes_per_s": ("system.disk.io_read_bytes_per_s", "bytes/s"),
    "disk_io_write_bytes_per_s": ("system.disk.io_write_bytes_per_s", "bytes/s"),
    "network_in_bytes_per_s": ("system.network.in_bytes_per_s", "bytes/s"),
    "network_out_bytes_per_s": ("system.network.out_bytes_per_s", "bytes/s"),
}

LOG_SOURCE_FIELDS = [
    "@timestamp",
    "host.name",
    "log.level",
    "service.name",
    "event.dataset",
    "event.category",
    "event.outcome",
    "message",
]
HIDDEN_FIELDS = ["incident_id"]  # answer key of the sample incidents: never returned
MAX_MESSAGE_CHARS = 1000

# ----------------------------------------------------------------------------- time
TIME_HELP = (
    "UTC. ISO-8601 like 2026-10-05T08:30:00Z (date only or an offset such as +07:00 also work), "
    "or relative to now: now, now-30m, now-6h, now-2d, now-1w."
)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_RELATIVE = re.compile(r"now(?:-(\d{1,4})([smhdw]))?")


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.strip())
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def parse_time(value: str, now: datetime) -> datetime:
    """ISO-8601 (naive ⇒ UTC) or `now[-<n><s|m|h|d|w>]` ⇒ aware UTC datetime."""
    v = value.strip()
    m = _RELATIVE.fullmatch(v.lower())
    if m:
        amount, unit = m.groups()
        return now if amount is None else now - timedelta(seconds=int(amount) * _UNIT_SECONDS[unit])
    try:
        return _parse_iso(v)
    except (ValueError, OverflowError):
        raise ToolError(
            f"Invalid time {value!r}. Use ISO-8601 UTC (e.g. 2026-10-05T08:30:00Z) "
            "or relative to now (now, now-30m, now-6h, now-2d)."
        ) from None


def resolve_window(start: str, end: str, now: datetime) -> tuple[datetime, datetime]:
    s, e = parse_time(start, now), parse_time(end, now)
    if s >= e:
        raise ToolError(f"`start` ({iso(s)}) must be before `end` ({iso(e)}).")
    return s, e


def fmt_ts(value: Any) -> str | None:
    """Epoch millis (aggregation keys) or ISO string (`_source`) ⇒ `YYYY-MM-DDTHH:MM:SSZ`."""
    if value is None:
        return None
    if isinstance(value, int | float):
        return iso(datetime.fromtimestamp(value / 1000, UTC))
    try:
        return iso(_parse_iso(str(value)))
    except (ValueError, OverflowError):
        return str(value)


# ----------------------------------------------------------------------------- bucket size
_INTERVAL_SECONDS = {
    "1m": 60,
    "5m": 300,
    "10m": 600,
    "15m": 900,
    "30m": 1800,
    "1h": 3600,
    "3h": 10800,
    "6h": 21600,
    "12h": 43200,
    "1d": 86400,
}
AUTO_TARGET_POINTS = 60  # `interval=auto` picks the smallest bucket giving at most this many points
MAX_POINTS = 500  # hard cap (LLM context budget)


def pick_interval(interval: str, start: datetime, end: datetime) -> str:
    span = (end - start).total_seconds()
    if interval == "auto":
        interval = next(
            (n for n, secs in _INTERVAL_SECONDS.items() if span / secs <= AUTO_TARGET_POINTS), "1d"
        )
    points = math.ceil(span / _INTERVAL_SECONDS[interval]) + 1  # +1: partial bucket at the edge
    if points > MAX_POINTS:
        raise ToolError(
            f"Interval {interval} over {iso(start)} .. {iso(end)} would return about {points} points "
            f"(max {MAX_POINTS}). Use a larger interval or a narrower time range."
        )
    return interval


# ----------------------------------------------------------------------------- query bodies
def _filters(
    start: datetime,
    end: datetime,
    *,
    host: str | None = None,
    service: str | None = None,
    levels: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = [
        {
            "range": {
                "@timestamp": {
                    "gte": iso(start),
                    "lte": iso(end),
                    "format": "strict_date_optional_time",
                }
            }
        }
    ]
    if host:
        filters.append({"term": {"host.name": host}})
    if service:
        filters.append({"term": {"service.name": service}})
    if levels:
        filters.append({"terms": {"log.level": list(levels)}})
    return filters


def logs_query(
    start: datetime,
    end: datetime,
    *,
    query: str | None = None,
    host: str | None = None,
    service: str | None = None,
    levels: Iterable[str] | None = None,
) -> dict[str, Any]:
    bool_q: dict[str, Any] = {
        "filter": _filters(start, end, host=host, service=service, levels=levels)
    }
    if query:
        bool_q["must"] = [
            {
                "simple_query_string": {
                    "query": query,
                    "fields": ["message"],
                    "default_operator": "and",
                }
            }
        ]
    return {"bool": bool_q}


def logs_search_body(
    query_dsl: dict[str, Any], *, order: str, limit: int, offset: int
) -> dict[str, Any]:
    return {
        "size": limit,
        "from": offset,
        "track_total_hits": True,
        "query": query_dsl,
        "sort": [{"@timestamp": {"order": order}}, {"_doc": {"order": "asc"}}],
        "_source": {"includes": LOG_SOURCE_FIELDS, "excludes": HIDDEN_FIELDS},
    }


def log_stats_body(query_dsl: dict[str, Any], interval: str) -> dict[str, Any]:
    return {
        "size": 0,
        "track_total_hits": True,
        "query": query_dsl,
        "aggs": {
            "by_level": {"terms": {"field": "log.level", "size": 10}},
            "by_service": {"terms": {"field": "service.name", "size": 20}},
            "by_host": {"terms": {"field": "host.name", "size": 20}},
            "timeline": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 1,
                },
                "aggs": {"by_level": {"terms": {"field": "log.level", "size": 10}}},
            },
        },
    }


def metric_series_body(
    host: str, metrics: list[str], agg: str, start: datetime, end: datetime, interval: str
) -> dict[str, Any]:
    return {
        "size": 0,
        "query": {"bool": {"filter": _filters(start, end, host=host)}},
        "aggs": {
            "series": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 1,
                },
                "aggs": {m: {agg: {"field": METRICS[m][0]}} for m in metrics},
            }
        },
    }


def metrics_summary_body(
    start: datetime, end: datetime, host: str | None, metrics: list[str]
) -> dict[str, Any]:
    per_host: dict[str, Any] = {
        "role": {"terms": {"field": "host.role", "size": 1}},
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
        "latest": {
            "top_hits": {
                "size": 1,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "_source": [METRICS[m][0] for m in metrics],
            }
        },
    }
    for m in metrics:
        field = METRICS[m][0]
        per_host[f"{m}__stats"] = {"stats": {"field": field}}
        per_host[f"{m}__p95"] = {"percentiles": {"field": field, "percents": [95]}}
        per_host[f"{m}__peak"] = {
            "top_hits": {"size": 1, "sort": [{field: {"order": "desc"}}], "_source": ["@timestamp"]}
        }
    return {
        "size": 0,
        "query": {"bool": {"filter": _filters(start, end, host=host)}},
        "aggs": {"hosts": {"terms": {"field": "host.name", "size": 50}, "aggs": per_host}},
    }


def overview_body(*, logs: bool) -> dict[str, Any]:
    aggs: dict[str, Any] = {
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}},
        "hosts": {
            "terms": {"field": "host.name", "size": 100},
            "aggs": {
                "role": {"terms": {"field": "host.role", "size": 1}},
                "ip": {"terms": {"field": "host.ip", "size": 1}},
            },
        },
    }
    if logs:
        aggs["services"] = {"terms": {"field": "service.name", "size": 50}}
        aggs["levels"] = {"terms": {"field": "log.level", "size": 10}}
    return {"size": 0, "track_total_hits": True, "aggs": aggs}


# ----------------------------------------------------------------------------- response parsing
def dig(obj: Any, *path: str) -> Any:
    """Safe nested `dict.get`: None when any level is missing or not a dict."""
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _num(value: Any) -> float | None:
    return None if value is None else round(float(value), 2)


def clip(text: str, limit: int = MAX_MESSAGE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + "… [truncated]"


def total_hits(resp: dict[str, Any]) -> int:
    return int(dig(resp, "hits", "total", "value") or 0)


def parse_log_hit(hit: dict[str, Any]) -> dict[str, Any]:
    s = hit.get("_source") or {}
    return {
        "timestamp": fmt_ts(s.get("@timestamp")),
        "host": dig(s, "host", "name"),
        "level": dig(s, "log", "level"),
        "service": dig(s, "service", "name"),
        "dataset": dig(s, "event", "dataset"),
        "category": dig(s, "event", "category"),
        "outcome": dig(s, "event", "outcome"),
        "message": clip(str(s.get("message") or "")),
    }


def parse_counts(agg: Any) -> dict[str, int]:
    """terms aggregation ⇒ {key: doc_count}."""
    return {str(b["key"]): int(b["doc_count"]) for b in dig(agg, "buckets") or []}


def parse_keys(agg: Any) -> list[str]:
    return [str(b["key"]) for b in dig(agg, "buckets") or []]


def _first_key(agg: Any) -> str | None:
    keys = parse_keys(agg)
    return keys[0] if keys else None


def parse_timeline(agg: Any) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": fmt_ts(b["key"]),
            "count": int(b["doc_count"]),
            "by_level": parse_counts(b.get("by_level")),
        }
        for b in dig(agg, "buckets") or []
    ]


def parse_series(resp: dict[str, Any], metrics: list[str]) -> list[dict[str, Any]]:
    return [
        {"timestamp": fmt_ts(b["key"]), "values": {m: _num(dig(b, m, "value")) for m in metrics}}
        for b in dig(resp, "aggregations", "series", "buckets") or []
    ]


def parse_summary(resp: dict[str, Any], metrics: list[str]) -> list[dict[str, Any]]:
    hosts = []
    for b in dig(resp, "aggregations", "hosts", "buckets") or []:
        latest_hits = dig(b, "latest", "hits", "hits") or []
        latest_src = (latest_hits[0].get("_source") if latest_hits else None) or {}
        stats = []
        for m in metrics:
            field, unit = METRICS[m]
            peak_hits = dig(b, f"{m}__peak", "hits", "hits") or []
            stats.append(
                {
                    "metric": m,
                    "unit": unit,
                    "latest": _num(dig(latest_src, *field.split("."))),
                    "min": _num(dig(b, f"{m}__stats", "min")),
                    "avg": _num(dig(b, f"{m}__stats", "avg")),
                    "p95": _num(dig(b, f"{m}__p95", "values", "95.0")),
                    "max": _num(dig(b, f"{m}__stats", "max")),
                    "peak_at": fmt_ts(dig(peak_hits[0], "_source", "@timestamp"))
                    if peak_hits
                    else None,
                }
            )
        hosts.append(
            {
                "host": str(b["key"]),
                "role": _first_key(b.get("role")),
                "samples": int(b["doc_count"]),
                "first_sample": fmt_ts(dig(b, "first", "value")),
                "last_sample": fmt_ts(dig(b, "last", "value")),
                "metrics": stats,
            }
        )
    return hosts


def parse_source(resp: dict[str, Any]) -> dict[str, Any]:
    """Overview of one index: document count and first/last timestamp."""
    return {
        "documents": total_hits(resp),
        "first_timestamp": fmt_ts(dig(resp, "aggregations", "first", "value")),
        "last_timestamp": fmt_ts(dig(resp, "aggregations", "last", "value")),
    }


def parse_hosts(resp: dict[str, Any]) -> dict[str, dict[str, str | None]]:
    """host name ⇒ {role, ip}."""
    return {
        str(b["key"]): {"role": _first_key(b.get("role")), "ip": _first_key(b.get("ip"))}
        for b in dig(resp, "aggregations", "hosts", "buckets") or []
    }
