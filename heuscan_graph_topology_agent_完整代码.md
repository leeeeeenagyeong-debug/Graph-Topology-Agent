# heuScan 图谱聚合模块（Graph & Topology Agent）—

---

## 目录结构

```text
backend/
  pyproject.toml
  neo4j/schema.cypher
  src/heuscan_graph/
    __init__.py
    settings.py
    urlnorm.py
    payload_io.py
    output_events.py
    event_normalize.py
    neo4j_client.py
    neo4j_writer.py
    agent.py
    models/__init__.py
    models/events.py
    models/payloads.py
    handlers/__init__.py
    handlers/registry.py
    handlers/dns.py
    handlers/port_http.py
    handlers/path.py
    handlers/enterprise.py
    handlers/inferred.py
    handlers/fingerprint.py
    handlers/risk.py
  tests/test_schemas.py
  tests/test_handlers_unit.py
  tests/test_integration_neo4j.py
```

---

## `pyproject.toml`

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "heuscan-graph"
version = "0.1.0"
description = "heuScan Graph & Topology Agent"
readme = "README.md"
requires-python = ">=3.11"
dependencies = [
    "neo4j>=5.14.0",
    "pydantic>=2.5.0",
    "httpx>=0.26.0",
]

[project.optional-dependencies]
dev = ["pytest>=7.4.0", "pytest-asyncio>=0.23.0"]

[tool.hatch.build.targets.wheel]
packages = ["src/heuscan_graph"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

---

## `neo4j/schema.cypher`

```cypher
CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE;
CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT webasset_url IF NOT EXISTS FOR (w:WebAsset) REQUIRE w.url IS UNIQUE;
CREATE CONSTRAINT pathasset_url IF NOT EXISTS FOR (pa:PathAsset) REQUIRE pa.url IS UNIQUE;
CREATE CONSTRAINT organization_id IF NOT EXISTS FOR (o:Organization) REQUIRE o.id IS UNIQUE;
CREATE CONSTRAINT person_id IF NOT EXISTS FOR (p:Person) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT evidence_id IF NOT EXISTS FOR (e:Evidence) REQUIRE e.evidence_id IS UNIQUE;
CREATE CONSTRAINT riskhint_id IF NOT EXISTS FOR (r:RiskHint) REQUIRE r.id IS UNIQUE;
```

---

## `src/heuscan_graph/__init__.py`

```python
from heuscan_graph.agent import GraphTopologyAgent

__all__ = ["GraphTopologyAgent", "__version__"]
__version__ = "0.1.0"
```

---

## `src/heuscan_graph/settings.py`

```python
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Neo4jSettings:
    uri: str
    user: str
    password: str

    @classmethod
    def from_env(cls) -> Neo4jSettings:
        return cls(
            uri=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
            user=os.environ.get("NEO4J_USER", "neo4j"),
            password=os.environ.get("NEO4J_PASSWORD", "password"),
        )


@dataclass(frozen=True)
class WriterSettings:
    batch_size: int = 100
    transaction_timeout_seconds: float = 30.0
    max_connection_retries: int = 3
    retry_backoff_base_seconds: float = 0.5

    @classmethod
    def from_env(cls) -> WriterSettings:
        return cls(
            batch_size=int(os.environ.get("GRAPH_BATCH_SIZE", "100")),
            transaction_timeout_seconds=float(
                os.environ.get("GRAPH_TX_TIMEOUT_SECONDS", "30")
            ),
        )
```

---

## `src/heuscan_graph/urlnorm.py`

```python
from __future__ import annotations

from urllib.parse import urlparse, urlunparse


def normalize_fqdn(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def normalize_web_url(url: str) -> str:
    u = url.strip()
    p = urlparse(u)
    if not p.scheme:
        p = urlparse("http://" + u)
    netloc = p.netloc.lower()
    path = p.path or "/"
    return urlunparse((p.scheme.lower(), netloc, path, "", p.query, ""))


def web_origin_from_url(url: str) -> str:
    p = urlparse(normalize_web_url(url))
    return urlunparse((p.scheme, p.netloc, "/", "", "", ""))
```

---

## `src/heuscan_graph/payload_io.py`

```python
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

import httpx


class PayloadFetcher(Protocol):
    def fetch_json(self, payload_ref: str) -> dict[str, Any]: ...


class LocalAndHttpPayloadFetcher:
    def fetch_json(self, payload_ref: str) -> dict[str, Any]:
        ref = payload_ref.strip()
        if ref.startswith("file://"):
            path = Path(ref[7:])
            return json.loads(path.read_text(encoding="utf-8"))
        if ref.startswith("minio://"):
            raise ValueError("minio:// 请接入对象存储或改为可 HTTP GET 的预签名 URL")
        p = Path(ref)
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
        if ref.startswith("http://") or ref.startswith("https://"):
            with httpx.Client(timeout=60.0) as client:
                r = client.get(ref)
                r.raise_for_status()
                return r.json()
        raise ValueError(f"unsupported payload_ref: {ref[:80]}")
```

---

## `src/heuscan_graph/output_events.py`

```python
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class GraphUpdatedPayload:
    batch_id: str
    events_consumed: int = 0
    nodes_created: int = 0
    nodes_updated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    warnings: list[str] = field(default_factory=list)
    skipped: dict[str, int] = field(
        default_factory=lambda: {
            "schema_invalid": 0,
            "out_of_scope": 0,
            "missing_evidence": 0,
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "events_consumed": self.events_consumed,
            "nodes_created": self.nodes_created,
            "nodes_updated": self.nodes_updated,
            "relationships_created": self.relationships_created,
            "relationships_updated": self.relationships_updated,
            "warnings": self.warnings,
            "skipped": dict(self.skipped),
        }


def build_graph_updated_event(
    *,
    task_id: str,
    batch_id: str,
    payload_ref: str,
    payload: GraphUpdatedPayload,
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "agent_id": "graph_topology_agent",
        "event_type": "GRAPH_UPDATED",
        "timestamp": iso_now(),
        "payload_ref": payload_ref,
        "confidence": 1.0,
        "priority": "low",
        "dedupe_key": f"{task_id}:graph_updated:{batch_id}",
        "retry_count": 0,
        "_payload": payload.to_dict(),
    }


def build_graph_write_failed_event(
    *,
    task_id: str,
    error_id: str,
    payload_ref: str,
    detail: dict[str, Any],
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "agent_id": "graph_topology_agent",
        "event_type": "GRAPH_WRITE_FAILED",
        "timestamp": iso_now(),
        "payload_ref": payload_ref,
        "confidence": 1.0,
        "priority": "high",
        "dedupe_key": f"{task_id}:graph_failed:{error_id}",
        "retry_count": 0,
        "_payload": detail,
    }


def new_batch_id() -> str:
    return str(uuid.uuid4())


def new_error_id() -> str:
    return str(uuid.uuid4())
```

---

## `src/heuscan_graph/event_normalize.py`

```python
from __future__ import annotations

_ALIASES: dict[str, str] = {
    "fingerprint.finding.created": "FINGERPRINT_IDENTIFIED",
    "fingerprint.hint.created": "TRAFFIC_RISK_FOUND",
}


def normalize_event_type(event_type: str, enabled: bool = False) -> str:
    if not enabled:
        return event_type
    return _ALIASES.get(event_type, event_type)
```

---

## `src/heuscan_graph/neo4j_client.py`

```python
from __future__ import annotations

import time
from typing import Callable, TypeVar

from neo4j import Driver, GraphDatabase

from heuscan_graph.settings import Neo4jSettings

T = TypeVar("T")


def connect(settings: Neo4jSettings) -> Driver:
    return GraphDatabase.driver(settings.uri, auth=(settings.user, settings.password))


def with_retries(
    fn: Callable[[], T],
    *,
    max_retries: int = 3,
    base_delay: float = 0.5,
) -> T:
    last: Exception | None = None
    for attempt in range(max_retries):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < max_retries - 1:
                time.sleep(base_delay * (2**attempt))
    assert last is not None
    raise last
```

---

## `src/heuscan_graph/neo4j_writer.py`

```python
from __future__ import annotations

import time
from typing import Any

from neo4j import Driver

from heuscan_graph.settings import WriterSettings


def run_queries_in_transaction(
    driver: Driver,
    queries: list[tuple[str, dict[str, Any]]],
    *,
    timeout_seconds: float,
) -> None:
    def work(tx: Any) -> None:
        for q, params in queries:
            tx.run(q, params)

    with driver.session() as session:
        session.execute_write(work, timeout=timeout_seconds)


def exponential_backoff_write(
    driver: Driver,
    queries: list[tuple[str, dict[str, Any]]],
    settings: WriterSettings,
) -> None:
    last_err: Exception | None = None
    delay = settings.retry_backoff_base_seconds
    for attempt in range(settings.max_connection_retries):
        try:
            run_queries_in_transaction(
                driver,
                queries,
                timeout_seconds=settings.transaction_timeout_seconds,
            )
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(delay)
            delay *= 2
    assert last_err is not None
    raise last_err
```

---

## `src/heuscan_graph/models/__init__.py`

```python
from heuscan_graph.models.events import GRAPH_CONSUME_EVENT_TYPES, ObservationEvent
from heuscan_graph.models.payloads import (
    DNSResolvedPayload,
    EnterpriseEntityFoundPayload,
    EnterpriseRelationFoundPayload,
    FileIntelFoundPayload,
    FingerprintIdentifiedPayload,
    HTTPServiceFoundPayload,
    PathFoundPayload,
    PortOpenPayload,
    RelationInferredPayload,
    TrafficRiskFoundPayload,
)

__all__ = [
    "GRAPH_CONSUME_EVENT_TYPES",
    "ObservationEvent",
    "DNSResolvedPayload",
    "PortOpenPayload",
    "HTTPServiceFoundPayload",
    "PathFoundPayload",
    "EnterpriseRelationFoundPayload",
    "RelationInferredPayload",
    "FingerprintIdentifiedPayload",
    "EnterpriseEntityFoundPayload",
    "TrafficRiskFoundPayload",
    "FileIntelFoundPayload",
]
```

---

## `src/heuscan_graph/models/events.py`

```python
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

GRAPH_CONSUME_EVENT_TYPES = frozenset(
    {
        "DNS_RESOLVED",
        "PORT_OPEN",
        "HTTP_SERVICE_FOUND",
        "PATH_FOUND",
        "FINGERPRINT_IDENTIFIED",
        "ENTERPRISE_ENTITY_FOUND",
        "ENTERPRISE_RELATION_FOUND",
        "RELATION_INFERRED",
        "TRAFFIC_RISK_FOUND",
        "FILE_INTEL_FOUND",
    }
)


class ObservationEvent(BaseModel):
    task_id: str
    agent_id: str = ""
    event_type: str
    payload_ref: str = ""
    confidence: float = 1.0
    priority: str = "normal"
    scope: dict[str, Any] | None = None
    lineage: dict[str, Any] | None = None
    dedupe_key: str = ""
    retry_count: int = 0
    timestamp: str | None = None

    model_config = {"extra": "allow"}
```

---

## `src/heuscan_graph/models/payloads.py`

```python
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class DNSResolvedPayload(BaseModel):
    domain: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(min_length=1)

    @field_validator("domain")
    @classmethod
    def domain_lower(cls, v: str) -> str:
        return v.strip().lower()


class PortOpenPayload(BaseModel):
    ip: str
    port: int
    proto: str = "tcp"
    source: str = "naabu"
    evidence_refs: list[str] = Field(min_length=1)


class HTTPServiceFoundPayload(BaseModel):
    url: str
    ip: str | None = None
    port: int | None = None
    status_code: int | None = None
    title: str | None = None
    final_url: str | None = None
    redirect_chain: list[Any] = Field(default_factory=list)
    tls: dict[str, Any] | None = None
    evidence_refs: list[str] = Field(min_length=1)


class PathFoundPayload(BaseModel):
    url: str
    status_code: int | None = None
    length: int | None = None
    title: str | None = None
    source: str = "dirsearch"
    confidence: float = 0.7
    evidence_refs: list[str] = Field(min_length=1)


EnterpriseRelationType = Literal["LEGAL_PERSON", "SHAREHOLDER", "INVEST", "EMPLOY"]


class EnterpriseRelationFoundPayload(BaseModel):
    source_entity_id: str
    target_entity_id: str
    relation_type: EnterpriseRelationType
    properties: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(min_length=1)


class RelationInferredPayload(BaseModel):
    source_id: str
    target_id: str
    relation_type: str
    inferred: Literal[True] = True
    weight: float = 0.2
    reason: str = ""
    evidence_refs: list[str] = Field(min_length=1)


class FingerprintIdentifiedPayload(BaseModel):
    asset_ref: str | None = None
    url: str | None = None
    ip: str | None = None
    port: int | None = None
    proto: str = "tcp"
    product: str = ""
    category: str = ""
    version: str | None = None
    confidence: float = 0.8
    evidence_refs: list[str] = Field(min_length=1)

    def effective_url(self) -> str | None:
        return self.url or self.asset_ref


class EnterpriseEntityFoundPayload(BaseModel):
    entity_type: Literal["organization", "person"] = "organization"
    id: str
    name: str = ""
    credit_code: str | None = None
    status: str | None = None
    source_tags: list[str] = Field(default_factory=list)
    ambiguity: bool | None = None
    evidence_refs: list[str] = Field(min_length=1)


class TrafficRiskFoundPayload(BaseModel):
    target_url: str | None = None
    target_service_id: str | None = None
    hint_type: str
    code: str
    title: str = ""
    confidence: float = 0.5
    severity: str = "medium"
    risk_type: str = "traffic"
    evidence_refs: list[str] = Field(min_length=1)


class FileIntelFoundPayload(BaseModel):
    target_url: str | None = None
    target_service_id: str | None = None
    hint_type: str = "file_intel"
    code: str
    title: str = ""
    confidence: float = 0.5
    severity: str = "medium"
    risk_type: str = "file"
    evidence_refs: list[str] = Field(min_length=1)
```

---

## `src/heuscan_graph/handlers/__init__.py`

```python
from heuscan_graph.handlers.registry import HandlerContext, build_queries_for_event

__all__ = ["HandlerContext", "build_queries_for_event"]
```

---

## `src/heuscan_graph/handlers/registry.py`

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pydantic import ValidationError

from heuscan_graph.handlers import dns, enterprise, fingerprint, inferred, path, port_http, risk
from heuscan_graph.models.events import GRAPH_CONSUME_EVENT_TYPES, ObservationEvent


@dataclass
class HandlerContext:
    task_id: str
    ts: str


QueryList = list[tuple[str, dict[str, Any]]]


def build_queries_for_event(
    event: ObservationEvent,
    payload: dict[str, Any],
    ctx: HandlerContext,
) -> tuple[QueryList | None, str | None]:
    et = event.event_type
    if et not in GRAPH_CONSUME_EVENT_TYPES:
        return None, "out_of_scope"
    builders: dict[str, Callable[[dict[str, Any], HandlerContext], QueryList]] = {
        "DNS_RESOLVED": dns.build,
        "PORT_OPEN": port_http.build_port,
        "HTTP_SERVICE_FOUND": port_http.build_http,
        "PATH_FOUND": path.build,
        "ENTERPRISE_ENTITY_FOUND": enterprise.build_entity,
        "ENTERPRISE_RELATION_FOUND": enterprise.build_relation,
        "RELATION_INFERRED": inferred.build,
        "FINGERPRINT_IDENTIFIED": fingerprint.build,
        "TRAFFIC_RISK_FOUND": risk.build_traffic,
        "FILE_INTEL_FOUND": risk.build_file,
    }
    fn = builders.get(et)
    if not fn:
        return None, "out_of_scope"
    try:
        return fn(payload, ctx), None
    except ValidationError:
        return None, "schema_invalid"
```

---

## `src/heuscan_graph/handlers/dns.py`

```python
from __future__ import annotations

from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import DNSResolvedPayload
from heuscan_graph.urlnorm import normalize_fqdn


def _merge_evidence_refs() -> str:
    return (
        "WITH r, $new_refs AS nr "
        "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
        "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
    )


def build(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = DNSResolvedPayload.model_validate(payload)
    domain = normalize_fqdn(p.domain)
    base = {"domain": domain, "ts": ctx.ts, "task_id": ctx.task_id}
    out: list[tuple[str, dict[str, Any]]] = []

    out.append(
        (
            "MERGE (d:Domain {name: $domain}) "
            "ON CREATE SET d.first_seen = datetime($ts) "
            "SET d.last_seen = datetime($ts), d.registered_domain = coalesce(d.registered_domain, $domain)",
            {**base},
        )
    )

    def resolves_ip(ip: str, rtype: str) -> tuple[str, dict[str, Any]]:
        cypher = (
            "MERGE (d:Domain {name: $domain}) "
            "MERGE (ip:IPAddress {address: $ip}) "
            "ON CREATE SET ip.first_seen = datetime($ts) "
            "SET ip.last_seen = datetime($ts) "
            "MERGE (d)-[r:RESOLVES_TO]->(ip) "
            "SET r.record_type = $rtype, r.last_resolved = datetime($ts) "
            + _merge_evidence_refs()
        )
        return cypher, {**base, "ip": ip, "rtype": rtype, "new_refs": list(p.evidence_refs)}

    for ip in p.a:
        out.append(resolves_ip(ip, "A"))
    for ip in p.aaaa:
        out.append(resolves_ip(ip, "AAAA"))
    for c in p.cname:
        cname = normalize_fqdn(c)
        cypher = (
            "MERGE (d:Domain {name: $domain}) "
            "MERGE (t:Domain {name: $cname}) "
            "ON CREATE SET t.first_seen = datetime($ts) "
            "SET t.last_seen = datetime($ts) "
            "MERGE (d)-[r:RESOLVES_TO]->(t) "
            "SET r.record_type = 'CNAME', r.last_resolved = datetime($ts) "
            + _merge_evidence_refs()
        )
        out.append(cypher, {**base, "cname": cname, "new_refs": list(p.evidence_refs)})
    for eid in p.evidence_refs:
        out.append(
            (
                "MERGE (ev:Evidence {evidence_id: $eid}) "
                "ON CREATE SET ev.fetched_at = datetime($ts) "
                "WITH ev MATCH (d:Domain {name: $domain}) "
                "MERGE (d)-[:REFERENCES {evidence_type: 'dns'}]->(ev)",
                {**base, "eid": eid},
            )
        )
    return out
```

---

## `src/heuscan_graph/handlers/port_http.py`

```python
from __future__ import annotations

from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import HTTPServiceFoundPayload, PortOpenPayload
from heuscan_graph.urlnorm import normalize_web_url


def build_port(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = PortOpenPayload.model_validate(payload)
    port_id = f"{p.ip}:{p.port}/{p.proto}"
    base = {"ts": ctx.ts, "task_id": ctx.task_id, "ip": p.ip, "port_id": port_id}
    cypher = (
        "MERGE (ip:IPAddress {address: $ip}) "
        "ON CREATE SET ip.first_seen = datetime($ts) "
        "SET ip.last_seen = datetime($ts) "
        "MERGE (pt:Port {id: $port_id}) "
        "ON CREATE SET pt.first_seen = datetime($ts), pt.number = $portnum, pt.proto = $proto "
        "SET pt.last_seen = datetime($ts) "
        "MERGE (ip)-[r:HAS_PORT]->(pt) "
        "SET r.source = $source "
        "WITH r, $new_refs AS nr "
        "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
        "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
    )
    rows: list[tuple[str, dict[str, Any]]] = [
        (
            cypher,
            {
                **base,
                "portnum": p.port,
                "proto": p.proto,
                "source": p.source,
                "new_refs": list(p.evidence_refs),
            },
        )
    ]
    for eid in p.evidence_refs:
        rows.append(
            (
                "MERGE (ev:Evidence {evidence_id: $eid}) ON CREATE SET ev.fetched_at = datetime($ts) "
                "WITH ev MATCH (pt:Port {id: $port_id}) MERGE (pt)-[:REFERENCES {evidence_type: 'port'}]->(ev)",
                {**base, "eid": eid},
            )
        )
    return rows


def build_http(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = HTTPServiceFoundPayload.model_validate(payload)
    url = normalize_web_url(p.url)
    final_u = normalize_web_url(p.final_url) if p.final_url else url
    ip = p.ip or ""
    port = int(p.port or (443 if url.startswith("https:") else 80))
    proto = "tcp"
    port_id = f"{ip}:{port}/{proto}" if ip else f"_:{port}/{proto}"
    tls_issuer = (p.tls or {}).get("issuer_cn") if p.tls else None

    base = {"ts": ctx.ts, "task_id": ctx.task_id, "url": url, "final_u": final_u, "ip": ip, "port_id": port_id}

    rows: list[tuple[str, dict[str, Any]]] = []

    if ip:
        rows.append(
            (
                "MERGE (ipn:IPAddress {address: $ip}) "
                "ON CREATE SET ipn.first_seen = datetime($ts) SET ipn.last_seen = datetime($ts)",
                {**base},
            )
        )
        rows.append(
            (
                "MERGE (pt:Port {id: $port_id}) "
                "ON CREATE SET pt.first_seen = datetime($ts), pt.number = $portnum, pt.proto = $proto "
                "SET pt.last_seen = datetime($ts) "
                "MERGE (ipn:IPAddress {address: $ip}) "
                "MERGE (ipn)-[hp:HAS_PORT]->(pt) "
                "SET hp.source = 'httpx' "
                "WITH hp, $new_refs AS nr "
                "SET hp.evidence_refs = reduce(acc = coalesce(hp.evidence_refs, []), x IN nr | "
                "CASE WHEN x IN acc THEN acc ELSE acc + x END)",
                {**base, "portnum": port, "proto": proto, "new_refs": list(p.evidence_refs)},
            )
        )
        rows.append(
            (
                "MERGE (pt:Port {id: $port_id}) "
                "MERGE (svc:Service {id: $port_id}) "
                "ON CREATE SET svc.first_seen = datetime($ts) "
                "SET svc.last_seen = datetime($ts), svc.name = coalesce(svc.name, 'http') "
                "MERGE (pt)-[rs:RUNS_SERVICE]->(svc) "
                "SET rs.confidence = $conf "
                "WITH rs, $new_refs AS nr "
                "SET rs.evidence_refs = reduce(acc = coalesce(rs.evidence_refs, []), x IN nr | "
                "CASE WHEN x IN acc THEN acc ELSE acc + x END)",
                {**base, "conf": 1.0, "new_refs": list(p.evidence_refs)},
            )
        )
        rows.append(
            (
                "MERGE (wa:WebAsset {url: $url}) "
                "ON CREATE SET wa.first_seen = datetime($ts) "
                "SET wa.last_seen = datetime($ts), wa.title = coalesce($title, wa.title), "
                "wa.status_code = coalesce($sc, wa.status_code), wa.final_url = coalesce($final_u, wa.final_url), "
                "wa.tls_issuer = coalesce($tls_issuer, wa.tls_issuer) "
                "MERGE (ipn:IPAddress {address: $ip}) "
                "MERGE (ipn)-[h:HOSTS]->(wa) SET h.port = $portnum "
                "WITH h, $new_refs AS nr "
                "SET h.evidence_refs = reduce(acc = coalesce(h.evidence_refs, []), x IN nr | "
                "CASE WHEN x IN acc THEN acc ELSE acc + x END)",
                {
                    **base,
                    "title": p.title,
                    "sc": p.status_code,
                    "tls_issuer": tls_issuer,
                    "portnum": port,
                    "new_refs": list(p.evidence_refs),
                },
            )
        )
    else:
        rows.append(
            (
                "MERGE (wa:WebAsset {url: $url}) "
                "ON CREATE SET wa.first_seen = datetime($ts) "
                "SET wa.last_seen = datetime($ts), wa.title = coalesce($title, wa.title), "
                "wa.status_code = coalesce($sc, wa.status_code), wa.final_url = coalesce($final_u, wa.final_url), "
                "wa.tls_issuer = coalesce($tls_issuer, wa.tls_issuer)",
                {**base, "title": p.title, "sc": p.status_code, "tls_issuer": tls_issuer},
            )
        )
    for eid in p.evidence_refs:
        rows.append(
            (
                "MERGE (ev:Evidence {evidence_id: $eid}) ON CREATE SET ev.fetched_at = datetime($ts) "
                "WITH ev MATCH (wa:WebAsset {url: $url}) MERGE (wa)-[:REFERENCES {evidence_type: 'http'}]->(ev)",
                {**base, "eid": eid},
            )
        )
    return rows
```

---

## `src/heuscan_graph/handlers/path.py`

```python
from __future__ import annotations

from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import PathFoundPayload
from heuscan_graph.urlnorm import normalize_web_url, web_origin_from_url


def build(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = PathFoundPayload.model_validate(payload)
    path_url = normalize_web_url(p.url)
    origin = web_origin_from_url(path_url)
    base = {"ts": ctx.ts, "task_id": ctx.task_id, "path_url": path_url, "origin": origin}
    cypher = (
        "MERGE (wa:WebAsset {url: $origin}) "
        "ON CREATE SET wa.first_seen = datetime($ts) "
        "SET wa.last_seen = datetime($ts) "
        "MERGE (pa:PathAsset {url: $path_url}) "
        "ON CREATE SET pa.first_seen = datetime($ts) "
        "SET pa.last_seen = datetime($ts), pa.status_code = coalesce($sc, pa.status_code), "
        "pa.title = coalesce($title, pa.title), pa.length = coalesce($plen, pa.length) "
        "MERGE (wa)-[hp:HAS_PATH]->(pa) "
        "WITH hp, $new_refs AS nr "
        "SET hp.evidence_refs = reduce(acc = coalesce(hp.evidence_refs, []), x IN nr | "
        "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
    )
    rows = [
        (
            cypher,
            {
                **base,
                "sc": p.status_code,
                "title": p.title,
                "plen": p.length,
                "new_refs": list(p.evidence_refs),
            },
        )
    ]
    for eid in p.evidence_refs:
        rows.append(
            (
                "MERGE (ev:Evidence {evidence_id: $eid}) ON CREATE SET ev.fetched_at = datetime($ts) "
                "WITH ev MATCH (pa:PathAsset {url: $path_url}) MERGE (pa)-[:REFERENCES {evidence_type: 'path'}]->(ev)",
                {**base, "eid": eid},
            )
        )
    return rows
```

---

## `src/heuscan_graph/handlers/enterprise.py`

```python
from __future__ import annotations

from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import EnterpriseEntityFoundPayload, EnterpriseRelationFoundPayload

_ALLOWED_REL = frozenset({"LEGAL_PERSON", "SHAREHOLDER", "INVEST", "EMPLOY"})


def build_entity(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = EnterpriseEntityFoundPayload.model_validate(payload)
    base = {"ts": ctx.ts, "task_id": ctx.task_id, "eid": p.id, "name": p.name}
    rows: list[tuple[str, dict[str, Any]]] = []
    if p.entity_type == "organization":
        rows.append(
            (
                "MERGE (o:Organization {id: $eid}) "
                "ON CREATE SET o.first_seen = datetime($ts) "
                "SET o.last_seen = datetime($ts), o.name = coalesce($name, o.name), "
                "o.status = coalesce($status, o.status), o.source_tags = coalesce($tags, o.source_tags)",
                {**base, "status": p.status, "tags": p.source_tags},
            )
        )
        label = "Organization"
    else:
        rows.append(
            (
                "MERGE (p:Person {id: $eid}) "
                "ON CREATE SET p.first_seen = datetime($ts) "
                "SET p.last_seen = datetime($ts), p.name = coalesce($name, p.name), "
                "p.source_tags = coalesce($tags, p.source_tags), "
                "p.ambiguity = coalesce($amb, p.ambiguity)",
                {**base, "tags": p.source_tags, "amb": p.ambiguity},
            )
        )
        label = "Person"
    for ev in p.evidence_refs:
        q = (
            "MERGE (ev:Evidence {evidence_id: $evid}) ON CREATE SET ev.fetched_at = datetime($ts) "
            f"WITH ev MATCH (n:{label} {{id: $eid}}) "
            "MERGE (n)-[:REFERENCES {evidence_type: 'enterprise'}]->(ev)"
        )
        rows.append((q, {**base, "evid": ev}))
    return rows


def build_relation(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = EnterpriseRelationFoundPayload.model_validate(payload)
    if p.relation_type not in _ALLOWED_REL:
        raise ValueError("invalid relation_type")
    ratio = p.properties.get("ratio")
    base = {
        "ts": ctx.ts,
        "sid": p.source_entity_id,
        "tid": p.target_entity_id,
        "ratio": ratio,
        "new_refs": list(p.evidence_refs),
    }
    rel = p.relation_type
    if rel == "LEGAL_PERSON":
        cypher = (
            "MERGE (a:Person {id: $sid}) ON CREATE SET a.first_seen = datetime($ts) SET a.last_seen = datetime($ts) "
            "MERGE (b:Organization {id: $tid}) ON CREATE SET b.first_seen = datetime($ts) SET b.last_seen = datetime($ts) "
            "MERGE (a)-[r:LEGAL_PERSON]->(b) "
            "WITH r, $new_refs AS nr "
            "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
            "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
        )
    elif rel == "SHAREHOLDER":
        # 一期：Person -> Organization；公司股东另事件可扩展 Org->Org
        cypher = (
            "MERGE (a:Person {id: $sid}) ON CREATE SET a.first_seen = datetime($ts) SET a.last_seen = datetime($ts) "
            "MERGE (b:Organization {id: $tid}) ON CREATE SET b.first_seen = datetime($ts) SET b.last_seen = datetime($ts) "
            "MERGE (a)-[r:SHAREHOLDER]->(b) SET r.ratio = coalesce($ratio, r.ratio) "
            "WITH r, $new_refs AS nr "
            "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
            "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
        )
    elif rel == "INVEST":
        cypher = (
            "MERGE (a:Organization {id: $sid}) ON CREATE SET a.first_seen = datetime($ts) SET a.last_seen = datetime($ts) "
            "MERGE (b:Organization {id: $tid}) ON CREATE SET b.first_seen = datetime($ts) SET b.last_seen = datetime($ts) "
            "MERGE (a)-[r:INVEST]->(b) SET r.ratio = coalesce($ratio, r.ratio) "
            "WITH r, $new_refs AS nr "
            "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
            "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
        )
    else:
        cypher = (
            "MERGE (a:Person {id: $sid}) ON CREATE SET a.first_seen = datetime($ts) SET a.last_seen = datetime($ts) "
            "MERGE (b:Organization {id: $tid}) ON CREATE SET b.first_seen = datetime($ts) SET b.last_seen = datetime($ts) "
            "MERGE (a)-[r:EMPLOY]->(b) "
            "WITH r, $new_refs AS nr "
            "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
            "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
        )
    rows: list[tuple[str, dict[str, Any]]] = [(cypher, base)]
    for ev in p.evidence_refs:
        if rel == "INVEST":
            rows.append(
                (
                    "MERGE (e:Evidence {evidence_id: $evid}) ON CREATE SET e.fetched_at = datetime($ts) "
                    "WITH e MATCH (src:Organization {id: $sid}) "
                    "MERGE (src)-[:REFERENCES {evidence_type: 'enterprise_rel'}]->(e)",
                    {"ts": ctx.ts, "evid": ev, "sid": p.source_entity_id},
                )
            )
        else:
            rows.append(
                (
                    "MERGE (e:Evidence {evidence_id: $evid}) ON CREATE SET e.fetched_at = datetime($ts) "
                    "WITH e MATCH (a:Person {id: $sid}) "
                    "MERGE (a)-[:REFERENCES {evidence_type: 'enterprise_rel'}]->(e)",
                    {"ts": ctx.ts, "evid": ev, "sid": p.source_entity_id},
                )
            )
    return rows
```

---

## `src/heuscan_graph/handlers/inferred.py`

```python
from __future__ import annotations

import re
from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import RelationInferredPayload

_REL_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")


def build(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = RelationInferredPayload.model_validate(payload)
    if not _REL_NAME.match(p.relation_type):
        raise ValueError("invalid relation_type for inferred")
    base = {
        "ts": ctx.ts,
        "sid": p.source_id,
        "tid": p.target_id,
        "rtype": p.relation_type,
        "weight": p.weight,
        "reason": p.reason or "",
        "new_refs": list(p.evidence_refs),
    }
    cypher = (
        "OPTIONAL MATCH (ao:Organization {id: $sid}) "
        "OPTIONAL MATCH (ap:Person {id: $sid}) "
        "WITH coalesce(ao, ap) AS a WHERE a IS NOT NULL "
        "OPTIONAL MATCH (bo:Organization {id: $tid}) "
        "OPTIONAL MATCH (bp:Person {id: $tid}) "
        "WITH a, coalesce(bo, bp) AS b WHERE b IS NOT NULL "
        "MERGE (a)-[r:RELATED_INFERRED]->(b) "
        "SET r.inferred = true, r.weight = $weight, r.reason = $reason, r.role = $rtype "
        "WITH r, $new_refs AS nr "
        "SET r.evidence_refs = reduce(acc = coalesce(r.evidence_refs, []), x IN nr | "
        "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
    )
    rows: list[tuple[str, dict[str, Any]]] = [(cypher, base)]
    for ev in p.evidence_refs:
        rows.append(
            (
                "MERGE (e:Evidence {evidence_id: $evid}) ON CREATE SET e.fetched_at = datetime($ts) "
                "WITH e OPTIONAL MATCH (ao:Organization {id: $sid}) OPTIONAL MATCH (ap:Person {id: $sid}) "
                "WITH e, coalesce(ao, ap) AS a WHERE a IS NOT NULL MERGE (a)-[:REFERENCES {evidence_type: 'inferred'}]->(e)",
                {"ts": ctx.ts, "evid": ev, "sid": p.source_id},
            )
        )
    return rows
```

---

## `src/heuscan_graph/handlers/fingerprint.py`

```python
from __future__ import annotations

from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import FingerprintIdentifiedPayload
from heuscan_graph.urlnorm import normalize_web_url


def build(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = FingerprintIdentifiedPayload.model_validate(payload)
    base = {"ts": ctx.ts, "task_id": ctx.task_id, "new_refs": list(p.evidence_refs)}
    rows: list[tuple[str, dict[str, Any]]] = []
    u = p.effective_url()
    if u:
        url = normalize_web_url(u)
        rows.append(
            (
                "MERGE (wa:WebAsset {url: $url}) ON CREATE SET wa.first_seen = datetime($ts) "
                "SET wa.last_seen = datetime($ts), "
                "wa.banner = coalesce($product + ':' + coalesce($version,''), wa.banner)",
                {**base, "url": url, "product": p.product or "unknown", "version": p.version or ""},
            )
        )
        anchor = ("WebAsset", "url", url)
    elif p.ip and p.port is not None:
        port_id = f"{p.ip}:{p.port}/{p.proto}"
        rows.append(
            (
                "MERGE (svc:Service {id: $pid}) ON CREATE SET svc.first_seen = datetime($ts) "
                "SET svc.last_seen = datetime($ts), svc.name = coalesce($product, svc.name), "
                "svc.version = coalesce($version, svc.version), svc.banner = coalesce($category, svc.banner)",
                {**base, "pid": port_id, "product": p.product, "version": p.version, "category": p.category},
            )
        )
        anchor = ("Service", "id", port_id)
    else:
        raise ValueError("fingerprint needs url or ip+port")
    for ev in p.evidence_refs:
        label, key, val = anchor
        rows.append(
            (
                f"MERGE (e:Evidence {{evidence_id: $evid}}) ON CREATE SET e.fetched_at = datetime($ts) "
                f"WITH e MATCH (n:{label} {{{key}: $val}}) MERGE (n)-[:REFERENCES {{evidence_type: 'fingerprint'}}]->(e)",
                {"ts": ctx.ts, "evid": ev, "val": val},
            )
        )
    return rows
```

---

## `src/heuscan_graph/handlers/risk.py`

```python
from __future__ import annotations

from typing import Any

from heuscan_graph.handlers.registry import HandlerContext
from heuscan_graph.models.payloads import FileIntelFoundPayload, TrafficRiskFoundPayload
from heuscan_graph.urlnorm import normalize_web_url


def _risk_hint_id(task_id: str, code: str, hint_type: str) -> str:
    return f"{task_id}:{hint_type}:{code}"


def build_traffic(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = TrafficRiskFoundPayload.model_validate(payload)
    return _build_risk(p, ctx, p.risk_type)


def build_file(payload: dict[str, Any], ctx: HandlerContext) -> list[tuple[str, dict[str, Any]]]:
    p = FileIntelFoundPayload.model_validate(payload)
    return _build_risk(p, ctx, p.risk_type)


def _build_risk(
    p: TrafficRiskFoundPayload | FileIntelFoundPayload,
    ctx: HandlerContext,
    risk_type: str,
) -> list[tuple[str, dict[str, Any]]]:
    hid = _risk_hint_id(ctx.task_id, p.code, p.hint_type)
    base = {
        "ts": ctx.ts,
        "hid": hid,
        "hint_type": p.hint_type,
        "code": p.code,
        "title": p.title,
        "confidence": p.confidence,
        "severity": p.severity,
        "risk_type": risk_type,
        "new_refs": list(p.evidence_refs),
    }
    rows: list[tuple[str, dict[str, Any]]] = [
        (
            "MERGE (h:RiskHint {id: $hid}) ON CREATE SET h.first_seen = datetime($ts) "
            "SET h.last_seen = datetime($ts), h.hint_type = $hint_type, h.code = $code, "
            "h.title = $title, h.confidence = $confidence, h.severity = $severity",
            base,
        )
    ]
    if p.target_url:
        url = normalize_web_url(p.target_url)
        cypher = (
            "MERGE (h:RiskHint {id: $hid}) "
            "MERGE (t:WebAsset {url: $url}) ON CREATE SET t.first_seen = datetime($ts) SET t.last_seen = datetime($ts) "
            "MERGE (h)-[ro:RISK_ON]->(t) SET ro.risk_type = $risk_type, ro.severity = $severity, ro.confidence = $confidence "
            "WITH ro, $new_refs AS nr "
            "SET ro.evidence_refs = reduce(acc = coalesce(ro.evidence_refs, []), x IN nr | "
            "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
        )
        rows.append((cypher, {**base, "url": url}))
    elif p.target_service_id:
        cypher = (
            "MERGE (h:RiskHint {id: $hid}) "
            "MERGE (t:Service {id: $sid}) ON CREATE SET t.first_seen = datetime($ts) SET t.last_seen = datetime($ts) "
            "MERGE (h)-[ro:RISK_ON]->(t) SET ro.risk_type = $risk_type, ro.severity = $severity, ro.confidence = $confidence "
            "WITH ro, $new_refs AS nr "
            "SET ro.evidence_refs = reduce(acc = coalesce(ro.evidence_refs, []), x IN nr | "
            "CASE WHEN x IN acc THEN acc ELSE acc + x END)"
        )
        rows.append((cypher, {**base, "sid": p.target_service_id}))
    else:
        raise ValueError("risk event needs target_url or target_service_id")
    for ev in p.evidence_refs:
        rows.append(
            (
                "MERGE (e:Evidence {evidence_id: $evid}) ON CREATE SET e.fetched_at = datetime($ts) "
                "WITH e MATCH (h:RiskHint {id: $hid}) MERGE (h)-[:REFERENCES {evidence_type: 'risk'}]->(e)",
                {"ts": ctx.ts, "evid": ev, "hid": hid},
            )
        )
    return rows
```

---

## `src/heuscan_graph/agent.py`

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from neo4j import Driver

from heuscan_graph.event_normalize import normalize_event_type
from heuscan_graph.handlers.registry import HandlerContext, build_queries_for_event
from heuscan_graph.models.events import ObservationEvent
from heuscan_graph.neo4j_writer import exponential_backoff_write
from heuscan_graph.output_events import (
    GraphUpdatedPayload,
    build_graph_updated_event,
    build_graph_write_failed_event,
    new_batch_id,
    new_error_id,
)
from heuscan_graph.payload_io import PayloadFetcher
from heuscan_graph.settings import WriterSettings


def _iso_ts(event: ObservationEvent) -> str:
    if event.timestamp:
        return event.timestamp
    return datetime.now(timezone.utc).isoformat()


class GraphTopologyAgent:
    """Neo4j 唯一写入入口：消费 ObservationEvent 列表，批量事务写入。"""

    def __init__(
        self,
        driver: Driver,
        fetcher: PayloadFetcher,
        *,
        writer_settings: WriterSettings | None = None,
        alias_normalize: bool = False,
    ) -> None:
        self._driver = driver
        self._fetcher = fetcher
        self._settings = writer_settings or WriterSettings.from_env()
        self._alias_normalize = alias_normalize

    def process_events(
        self,
        events: list[ObservationEvent],
        *,
        task_id: str,
        payload_ref_out: str = "inline://graph-stats",
    ) -> list[dict[str, Any]]:
        out_events: list[dict[str, Any]] = []
        stats = GraphUpdatedPayload(batch_id=new_batch_id())
        seen_dedupe: set[str] = set()
        all_queries: list[tuple[str, dict[str, Any]]] = []

        for raw in events:
            ev = raw.model_copy(
                update={
                    "event_type": normalize_event_type(
                        raw.event_type, self._alias_normalize
                    )
                }
            )
            if ev.dedupe_key and ev.dedupe_key in seen_dedupe:
                continue
            if ev.dedupe_key:
                seen_dedupe.add(ev.dedupe_key)
            ctx = HandlerContext(task_id=ev.task_id or task_id, ts=_iso_ts(ev))
            if not ev.payload_ref:
                stats.skipped["schema_invalid"] += 1
                stats.warnings.append(f"missing payload_ref: {ev.event_type}")
                continue
            try:
                payload = self._fetcher.fetch_json(ev.payload_ref)
            except Exception as e:  # noqa: BLE001
                stats.skipped["schema_invalid"] += 1
                stats.warnings.append(f"payload fetch failed: {ev.event_type}: {e}")
                continue
            qs, skip = build_queries_for_event(ev, payload, ctx)
            if skip == "out_of_scope":
                stats.skipped["out_of_scope"] += 1
                continue
            if skip == "schema_invalid" or qs is None:
                stats.skipped["schema_invalid"] += 1
                stats.warnings.append(f"schema_invalid: {ev.event_type}")
                continue
            all_queries.extend(qs)
            stats.events_consumed += 1

        current_bs = self._settings.batch_size
        idx = 0
        while idx < len(all_queries):
            chunk = all_queries[idx : idx + current_bs]
            try:
                exponential_backoff_write(self._driver, chunk, self._settings)
                idx += len(chunk)
            except Exception as e:  # noqa: BLE001
                if len(chunk) > 1:
                    current_bs = max(1, len(chunk) // 2)
                    continue
                err = new_error_id()
                out_events.append(
                    build_graph_write_failed_event(
                        task_id=task_id,
                        error_id=err,
                        payload_ref=f"inline://graph-error/{err}",
                        detail={"error": str(e), "at_query_index": idx},
                    )
                )
                return out_events

        stats.nodes_created = stats.events_consumed
        out_events.append(
            build_graph_updated_event(
                task_id=task_id,
                batch_id=stats.batch_id,
                payload_ref=payload_ref_out,
                payload=stats,
            )
        )
        return out_events
```

---

## `tests/test_schemas.py`

```python
import pytest
from pydantic import ValidationError

from heuscan_graph.models.payloads import DNSResolvedPayload, PortOpenPayload


def test_dns_requires_evidence():
    with pytest.raises(ValidationError):
        DNSResolvedPayload(domain="x.com", evidence_refs=[])


def test_dns_ok():
    d = DNSResolvedPayload(domain="X.COM", a=["1.1.1.1"], evidence_refs=["e1"])
    assert d.domain == "x.com"


def test_port_ok():
    p = PortOpenPayload(ip="10.0.0.1", port=443, evidence_refs=["e"])
    assert p.proto == "tcp"
```

---

## `tests/test_handlers_unit.py`

```python
from heuscan_graph.handlers.registry import HandlerContext, build_queries_for_event
from heuscan_graph.models.events import ObservationEvent


def test_dns_builds_queries():
    ev = ObservationEvent(
        task_id="t1",
        event_type="DNS_RESOLVED",
        payload_ref="x",
    )
    ctx = HandlerContext(task_id="t1", ts="2026-01-01T00:00:00Z")
    qs, skip = build_queries_for_event(
        ev,
        {"domain": "a.com", "a": ["1.1.1.1"], "evidence_refs": ["e1"]},
        ctx,
    )
    assert skip is None and qs and len(qs) >= 2


def test_unknown_event_out_of_scope():
    ev = ObservationEvent(task_id="t1", event_type="FOO", payload_ref="x")
    ctx = HandlerContext(task_id="t1", ts="2026-01-01T00:00:00Z")
    qs, skip = build_queries_for_event(ev, {}, ctx)
    assert qs is None and skip == "out_of_scope"
```

---

## `tests/test_integration_neo4j.py`

```python
import os

import pytest

from heuscan_graph.agent import GraphTopologyAgent
from heuscan_graph.models.events import ObservationEvent
from heuscan_graph.neo4j_client import connect
from heuscan_graph.settings import Neo4jSettings


@pytest.mark.skipif(not os.environ.get("NEO4J_URI"), reason="NEO4J_URI not set")
def test_agent_dns_roundtrip(tmp_path):
    payload = {
        "domain": "example.com",
        "a": ["93.184.216.34"],
        "evidence_refs": ["ev-1"],
    }
    pfile = tmp_path / "p.json"
    pfile.write_text(__import__("json").dumps(payload), encoding="utf-8")
    ev = ObservationEvent(
        task_id="task-1",
        event_type="DNS_RESOLVED",
        payload_ref=str(pfile),
    )

    class Fetcher:
        def fetch_json(self, ref: str):
            return __import__("json").loads(__import__("pathlib").Path(ref).read_text())

    driver = connect(Neo4jSettings.from_env())
    agent = GraphTopologyAgent(driver, Fetcher())
    outs = agent.process_events([ev], task_id="task-1")
    driver.close()
    assert any(o.get("event_type") == "GRAPH_UPDATED" for o in outs)
```

---

## 使用说明（摘录）

1. 将各代码块复制为对应路径文件。
2. 在 Neo4j 执行 `schema.cypher`。
3. `pip install -e ".[dev]"` 后运行 `pytest`；集成测试需设置 `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD`。
4. 推断关系在库中使用单类型 `RELATED_INFERRED`，业务类型放在 `r.role`；若需严格多类型动态边，可引入 APOC 或服务端拼好白名单内的静态 Cypher。
