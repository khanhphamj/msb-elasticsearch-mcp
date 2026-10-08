"""SRE MCP server: read-only tools over logs and metrics stored in Elasticsearch.

Deploy on AgentBase Runtime (or any Docker host) and attach to the MCP Gateway as a Custom Connector.
Runtime contract: 0.0.0.0:8080, GET /health 200 (no auth). MCP endpoint: POST /mcp (streamable HTTP,
stateless ⇒ scale to many replicas without sticky sessions). Connector URL = <runtime endpoint>/mcp.

The data is shared (no per-user data), so API Key 2LO is enough. Tools are scoped `logs.read` /
`metrics.read`. Arguments are validated before they reach Elasticsearch — see queries.py.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Annotated, Literal

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

import queries
from auth import build_verifier
from backend import Backend
from queries import Agg, Interval, LogLevel, MetricName
from settings import get_settings

settings = get_settings()
logging.basicConfig(level="INFO")
log = logging.getLogger(settings.server_name)

INSTRUCTIONS = (
    "Read-only SRE data: infrastructure logs and host metrics stored in Elasticsearch. Suggested flow: "
    "(1) get_overview for the hosts and the period that has data; (2) get_metrics_summary to see which "
    "metric is abnormal and when it peaked; (3) get_metrics for the shape of the curve; (4) get_log_stats "
    "and search_logs around that window (levels WARN/ERROR) to find the cause. All timestamps are UTC. "
    "The data may be historical, so use the period reported by get_overview rather than assuming 'now'."
)

verifier = build_verifier(settings)
backend = Backend(
    settings.backend_url,
    settings.backend_timeout_s,
    settings.backend_token,
    username=settings.backend_username,
    password=settings.backend_password,
)
mcp = FastMCP(
    settings.server_name,
    instructions=INSTRUCTIONS,
    host="0.0.0.0",
    port=settings.port,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
    token_verifier=verifier,
    auth=AuthSettings(
        issuer_url=settings.issuer or settings.resource_url,
        resource_server_url=settings.resource_url,
        required_scopes=settings.required_scopes or None,
        validate_token_resource=False,  # JwtVerifier checks `aud` itself (MCP_AUDIENCE)
    )
    if verifier
    else None,
)


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


# ----------------------------------------------------------------------------- helpers
class Forbidden(ToolError):
    pass


def require_scope(scope: str) -> None:
    tok = get_access_token()
    if tok is not None and settings.auth_mode != "none" and scope not in tok.scopes:
        raise Forbidden(f"Missing scope '{scope}'")


def _now() -> datetime:
    return datetime.now(UTC)  # one place to freeze the clock in tests


@contextmanager
def _upstream_shape(tool: str) -> Iterator[None]:
    """Elasticsearch answered 200 but not in the shape we expect ⇒ fail with a clean message (details in log)."""
    try:
        yield
    except (KeyError, IndexError, TypeError, ValueError, AttributeError):
        log.exception("unexpected Elasticsearch response shape tool=%s", tool)
        raise ToolError("Elasticsearch returned an unexpected response. Try again later.") from None


READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
HOST_PATTERN = r"^[A-Za-z0-9._-]{1,64}$"
MAX_OFFSET = 9900  # Elasticsearch result window is 10 000 (offset + limit)

Start = Annotated[
    str, Field(min_length=3, max_length=40, description="Window start. " + queries.TIME_HELP)
]
End = Annotated[
    str,
    Field(
        min_length=3,
        max_length=40,
        description="Window end, inclusive. Default: now. " + queries.TIME_HELP,
    ),
]
HostFilter = Annotated[
    str | None,
    Field(pattern=HOST_PATTERN, description="Exact host name, e.g. web-01 (see get_overview)"),
]
ServiceFilter = Annotated[
    str | None,
    Field(
        pattern=HOST_PATTERN,
        description="Exact service/logger name, e.g. nginx, postgres, kernel, sshd (see get_overview)",
    ),
]
LevelFilter = Annotated[
    list[LogLevel] | None,
    Field(max_length=4, description='Only these severities, e.g. ["WARN","ERROR"]. Default: all'),
]
TextQuery = Annotated[
    str | None,
    Field(
        max_length=200,
        description=(
            "Words to find in the log message; all words must match. Quotes = exact phrase, "
            '-word = exclude, a | b = either. Examples: "No space left", timeout -nginx'
        ),
    ),
]


# ----------------------------------------------------------------------------- output models
class HostInfo(BaseModel):
    name: str
    role: str | None
    ip: str | None


class SourceInfo(BaseModel):
    documents: int
    first_timestamp: str | None = Field(description="Oldest entry (UTC)")
    last_timestamp: str | None = Field(description="Newest entry (UTC)")


class Overview(BaseModel):
    server_time: str = Field(description="Current time on the server (UTC)")
    hosts: list[HostInfo]
    logs: SourceInfo
    log_services: list[str]
    log_levels: list[str]
    metrics: SourceInfo
    metric_names: list[str] = Field(description="Valid values for `metrics` in the metric tools")


class LogEntry(BaseModel):
    timestamp: str
    host: str
    level: str
    service: str
    dataset: str | None = None
    category: str | None = None
    outcome: str | None = None
    message: str


class LogPage(BaseModel):
    start: str = Field(description="Resolved window start (UTC)")
    end: str = Field(description="Resolved window end (UTC)")
    items: list[LogEntry]
    total: int = Field(description="All logs matching the filters in the window, across pages")
    next_offset: int | None = Field(
        description="Pass as `offset` to get the next page; null = last page"
    )


class TimelineBucket(BaseModel):
    timestamp: str = Field(description="Bucket start (UTC)")
    count: int
    by_level: dict[str, int]


class LogStats(BaseModel):
    start: str
    end: str
    interval: str = Field(description="Bucket size used for `timeline`")
    total: int
    by_level: dict[str, int]
    by_service: dict[str, int]
    by_host: dict[str, int]
    timeline: list[TimelineBucket] = Field(
        description="Buckets that contain logs (empty ones omitted)"
    )


class MetricPoint(BaseModel):
    timestamp: str = Field(description="Bucket start (UTC)")
    values: dict[str, float | None]


class MetricSeries(BaseModel):
    host: str
    start: str
    end: str
    interval: str
    agg: str
    units: dict[str, str]
    points: list[MetricPoint]
    note: str | None = None


class MetricStats(BaseModel):
    metric: str
    unit: str
    latest: float | None = Field(description="Value at the most recent sample in the window")
    min: float | None
    avg: float | None
    p95: float | None
    max: float | None
    peak_at: str | None = Field(description="Time of the highest sample (UTC)")


class HostMetrics(BaseModel):
    host: str
    role: str | None
    samples: int
    first_sample: str | None
    last_sample: str | None
    metrics: list[MetricStats]


class MetricsSummary(BaseModel):
    start: str
    end: str
    hosts: list[HostMetrics]
    note: str | None = None


# ----------------------------------------------------------------------------- tools
@mcp.tool(annotations=READ_ONLY)
async def get_overview() -> Overview:
    """START HERE. What data exists: the monitored hosts (name, role, IP), the period covered by the logs
    and by the metrics (first/last timestamp, UTC), the log services and levels, the metric names you can
    query, and the server's current time. The data may be historical: choose `start`/`end` for the other
    tools from the period reported here, because relative times such as now-1h can be empty.
    Requires scopes `logs.read` and `metrics.read`."""
    require_scope("logs.read")
    require_scope("metrics.read")
    logs_resp, metrics_resp = await asyncio.gather(
        backend.search(settings.logs_index, queries.overview_body(logs=True)),
        backend.search(settings.metrics_index, queries.overview_body(logs=False)),
    )
    with _upstream_shape("get_overview"):
        hosts = {**queries.parse_hosts(metrics_resp), **queries.parse_hosts(logs_resp)}
        return Overview(
            server_time=queries.iso(_now()),
            hosts=[HostInfo(name=n, **info) for n, info in sorted(hosts.items())],
            logs=SourceInfo(**queries.parse_source(logs_resp)),
            log_services=queries.parse_keys(queries.dig(logs_resp, "aggregations", "services")),
            log_levels=queries.parse_keys(queries.dig(logs_resp, "aggregations", "levels")),
            metrics=SourceInfo(**queries.parse_source(metrics_resp)),
            metric_names=list(queries.METRICS),
        )


@mcp.tool(annotations=READ_ONLY)
async def search_logs(
    start: Start,
    end: End = "now",
    query: TextQuery = None,
    host: HostFilter = None,
    service: ServiceFilter = None,
    levels: LevelFilter = None,
    order: Annotated[
        Literal["asc", "desc"],
        Field(description="desc = newest first (default), asc = oldest first"),
    ] = "desc",
    limit: Annotated[int, Field(ge=1, le=100, description="Page size")] = 50,
    offset: Annotated[
        int, Field(ge=0, le=MAX_OFFSET, description="From `next_offset` of the previous page")
    ] = 0,
) -> LogPage:
    """Search log lines (sshd, nginx, postgres, kernel, cron, systemd, app...) in a time window, newest
    first by default. Filter by host, service, severity and words in the message. Typical use: a metric
    spiked at some time ⇒ search that window with levels ["WARN","ERROR"] to find what the system
    reported. Paginated via `next_offset`. Requires scope `logs.read`."""
    require_scope("logs.read")
    s, e = queries.resolve_window(start, end, _now())
    dsl = queries.logs_query(s, e, query=query, host=host, service=service, levels=levels)
    body = queries.logs_search_body(dsl, order=order, limit=limit, offset=offset)
    resp = await backend.search(settings.logs_index, body)
    with _upstream_shape("search_logs"):
        items = [LogEntry(**queries.parse_log_hit(h)) for h in resp["hits"]["hits"]]
        total = queries.total_hits(resp)
        nxt = offset + len(items)
        page = LogPage(
            start=queries.iso(s),
            end=queries.iso(e),
            items=items,
            total=total,
            next_offset=nxt if nxt < total and nxt <= MAX_OFFSET else None,
        )
    log.info(
        "search_logs host=%s service=%s levels=%s returned=%d total=%d took_ms=%s",
        host,
        service,
        levels,
        len(items),
        total,
        resp.get("took"),
    )
    return page


@mcp.tool(annotations=READ_ONLY)
async def get_log_stats(
    start: Start,
    end: End = "now",
    query: TextQuery = None,
    host: HostFilter = None,
    service: ServiceFilter = None,
    levels: LevelFilter = None,
    interval: Annotated[
        Interval,
        Field(description="Timeline bucket size. auto (default) gives at most ~60 buckets"),
    ] = "auto",
) -> LogStats:
    """Count logs in a time window: totals by level, service and host, plus a timeline split by level.
    Cheaper than search_logs for questions like "when did the errors start?" or "which service logs the
    most errors?". Takes the same filters as search_logs. Requires scope `logs.read`."""
    require_scope("logs.read")
    s, e = queries.resolve_window(start, end, _now())
    iv = queries.pick_interval(interval, s, e)
    dsl = queries.logs_query(s, e, query=query, host=host, service=service, levels=levels)
    resp = await backend.search(settings.logs_index, queries.log_stats_body(dsl, iv))
    with _upstream_shape("get_log_stats"):
        aggs = resp.get("aggregations") or {}
        stats = LogStats(
            start=queries.iso(s),
            end=queries.iso(e),
            interval=iv,
            total=queries.total_hits(resp),
            by_level=queries.parse_counts(aggs.get("by_level")),
            by_service=queries.parse_counts(aggs.get("by_service")),
            by_host=queries.parse_counts(aggs.get("by_host")),
            timeline=[TimelineBucket(**b) for b in queries.parse_timeline(aggs.get("timeline"))],
        )
    log.info("get_log_stats host=%s total=%d interval=%s", host, stats.total, iv)
    return stats


@mcp.tool(annotations=READ_ONLY)
async def get_metrics(
    host: Annotated[
        str,
        Field(pattern=HOST_PATTERN, description="Exact host name, e.g. web-01 (see get_overview)"),
    ],
    metrics: Annotated[
        list[MetricName],
        Field(
            min_length=1,
            max_length=6,
            description='1-6 metric names, e.g. ["cpu_usage_pct","load_1m"]',
        ),
    ],
    start: Start,
    end: End = "now",
    interval: Annotated[
        Interval, Field(description="Bucket size. auto (default) gives at most ~60 points")
    ] = "auto",
    agg: Annotated[
        Agg,
        Field(
            description="How samples inside a bucket are combined: max (default, keeps spikes "
            "visible), avg (smooths), min"
        ),
    ] = "max",
) -> MetricSeries:
    """Time series of metrics for ONE host, downsampled (samples are 1 per minute). Units: *_pct = percent,
    *_bytes_per_s = bytes per second, load_* = load average, memory_used_bytes = bytes. Use
    get_metrics_summary first to learn which metric moved and when. Requires scope `metrics.read`."""
    require_scope("metrics.read")
    s, e = queries.resolve_window(start, end, _now())
    iv = queries.pick_interval(interval, s, e)
    names = list(dict.fromkeys(metrics))
    body = queries.metric_series_body(host, names, agg, s, e, iv)
    resp = await backend.search(settings.metrics_index, body)
    with _upstream_shape("get_metrics"):
        points = [MetricPoint(**p) for p in queries.parse_series(resp, names)]
        series = MetricSeries(
            host=host,
            start=queries.iso(s),
            end=queries.iso(e),
            interval=iv,
            agg=agg,
            units={m: queries.METRICS[m][1] for m in names},
            points=points,
            note=None
            if points
            else "No samples for this host in this window. Check the host name and the period "
            "(see get_overview).",
        )
    log.info("get_metrics host=%s metrics=%s points=%d interval=%s", host, names, len(points), iv)
    return series


@mcp.tool(annotations=READ_ONLY)
async def get_metrics_summary(
    start: Start,
    end: End = "now",
    host: Annotated[
        str | None,
        Field(pattern=HOST_PATTERN, description="Only this host. Default: every host"),
    ] = None,
    metrics: Annotated[
        list[MetricName] | None,
        Field(min_length=1, max_length=11, description="Only these metrics. Default: all of them"),
    ] = None,
) -> MetricsSummary:
    """For each host and metric over a time window: latest value, min, avg, p95, max and the time of the
    peak (`peak_at`). The fastest way to see which metric is abnormal and when it peaked, before drilling
    into get_metrics and search_logs. Requires scope `metrics.read`."""
    require_scope("metrics.read")
    s, e = queries.resolve_window(start, end, _now())
    names = list(dict.fromkeys(metrics or queries.METRICS))
    resp = await backend.search(
        settings.metrics_index, queries.metrics_summary_body(s, e, host, names)
    )
    with _upstream_shape("get_metrics_summary"):
        hosts = [HostMetrics(**h) for h in queries.parse_summary(resp, names)]
        summary = MetricsSummary(
            start=queries.iso(s),
            end=queries.iso(e),
            hosts=hosts,
            note=None
            if hosts
            else "No samples in this window. Check the host name and the period (see get_overview).",
        )
    log.info("get_metrics_summary host=%s metrics=%d hosts=%d", host, len(names), len(hosts))
    return summary


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
