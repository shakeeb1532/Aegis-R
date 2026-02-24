from __future__ import annotations
import typer
from pathlib import Path
import time
import uvicorn
import httpx

from noisegraph.outputs.console import ConsoleEmitter, print_decision
from noisegraph.outputs.jsonl import JsonlEmitter
from noisegraph.outputs.splunk_hec import SplunkHecEmitter
from noisegraph.outputs.datadog import DatadogEmitter

from noisegraph.config import EngineConfig
from noisegraph.api.server import create_app
from noisegraph.shipper.tailer import follow_file
from noisegraph.shipper.stdin import read_stdin
from noisegraph import __version__


def _build_emitters(
    emit: list[str],
    *,
    jsonl_path: Path | None,
    splunk_hec_url: str | None,
    splunk_token: str | None,
    splunk_index: str | None,
    splunk_sourcetype: str | None,
    dd_api_key: str | None,
    dd_site: str | None,
    dd_service: str | None,
    dd_source: str | None,
    dd_tags: str | None,
    only_keep: bool,
):
    emitters = []
    wanted = [e.strip().lower() for e in (emit or [])]
    if not wanted:
        wanted = ["console"]

    for e in wanted:
        if e in {"console", "stdout"}:
            emitters.append(ConsoleEmitter())
        elif e in {"jsonl"}:
            if not jsonl_path:
                raise typer.BadParameter("--jsonl-path is required when using --emit jsonl")
            emitters.append(JsonlEmitter(jsonl_path))
        elif e in {"splunk", "splunk-hec", "hec"}:
            if not splunk_hec_url:
                raise typer.BadParameter("--splunk-hec-url is required when using --emit splunk")
            if not splunk_token:
                raise typer.BadParameter("--splunk-token is required when using --emit splunk")
            emitters.append(
                SplunkHecEmitter(
                    hec_url=splunk_hec_url,
                    token=splunk_token,
                    index=splunk_index,
                    sourcetype=splunk_sourcetype or "noisegraph",
                    only_keep=only_keep,
                )
            )
        elif e in {"datadog", "dd"}:
            if not dd_api_key:
                raise typer.BadParameter("--dd-api-key is required when using --emit datadog")
            emitters.append(
                DatadogEmitter(
                    api_key=dd_api_key,
                    site=dd_site or "datadoghq.com",
                    service=dd_service,
                    source=dd_source,
                    tags=dd_tags,
                    only_keep=only_keep,
                )
            )
        else:
            raise typer.BadParameter(f"Unknown --emit value: {e}")
    return emitters

app = typer.Typer(help="noisegraph: standalone log shipper + baseline + behavioral graph noise reducer")
ship = typer.Typer(help="ship raw logs into the local engine")
app.add_typer(ship, name="ship")

@app.command()
def policy_check(
    path: Path = typer.Option(..., help="Path to log file"),
    policy: Path = typer.Option(..., help="Policy YAML path"),
    format: str = typer.Option("plain", help="plain or jsonl"),
    message_field: str = typer.Option("message", help="JSON field for message"),
    limit: int = typer.Option(1000, help="Max lines to scan"),
):
    from noisegraph.policy import load_policy
    from noisegraph.normalize.parser import parse_raw
    import json as _json

    pol = load_policy(policy)
    if not pol:
        typer.echo("Policy not found or empty.")
        raise typer.Exit(code=1)

    whitelist = 0
    blacklist = 0
    total = 0

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if total >= limit:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            total += 1
            if format == "jsonl":
                try:
                    obj = _json.loads(line)
                    msg = str(obj.get(message_field, "")) if isinstance(obj, dict) else line
                except Exception:
                    msg = line
            else:
                msg = line

            # naive templateization: reuse parser
            ev, _ = parse_raw(msg, source="policy", stream="policy")
            template = ev["template"]
            if pol.match_whitelist(template):
                whitelist += 1
            if pol.match_blacklist(template):
                blacklist += 1

    typer.echo(f"Scanned: {total}")
    typer.echo(f"Whitelist matches: {whitelist}")
    typer.echo(f"Blacklist matches: {blacklist}")

@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", help="Show version and exit", is_eager=True
    )
):
    if version:
        typer.echo(f"noisegraph {__version__}")
        raise typer.Exit()

@app.command()
def serve(
    db: Path = typer.Option(Path("./state/noisegraph.db"), help="SQLite DB path"),
    decisions: Path = typer.Option(Path("./state/decisions.jsonl"), help="Decisions JSONL path"),
    port: int = typer.Option(8099, help="Port"),
    host: str = typer.Option("127.0.0.1", help="Bind host"),
    policy: Path | None = typer.Option(None, help="Policy YAML path (whitelist/blacklist templates)"),
):
    cfg = EngineConfig(db_path=db, decisions_jsonl=decisions, policy_path=policy)
    api = create_app(cfg)
    uvicorn.run(api, host=host, port=port, log_level="info")

@ship.command("tail")
def ship_tail(
    path: Path = typer.Option(..., help="Path to log file to tail"),
    source: str = typer.Option("mac.local", help="Source/host label"),
    stream: str = typer.Option("file", help="Stream label"),
    engine_url: str = typer.Option("http://127.0.0.1:8099/ingest", help="Engine ingest URL"),
    batch_size: int = typer.Option(1, help="Batch size for ingest (1=disable)"),
    batch_interval: float = typer.Option(0.5, help="Max seconds to wait before sending a batch"),
    read_existing: bool = typer.Option(
        False,
        "--read-existing/--no-read-existing",
        help="Start at beginning of file (default: tail from end)",
    ),
    emit: list[str] = typer.Option(
        ["console"],
        "--emit",
        "-e",
        help="Emit decisions to sinks. Repeatable. Values: console, jsonl, splunk, datadog",
    ),
    jsonl_path: Path | None = typer.Option(None, help="Required when --emit jsonl"),
    # Splunk HEC
    splunk_hec_url: str | None = typer.Option(
        None,
        help="Splunk HEC base URL or event endpoint, e.g. https://splunk:8088 or https://splunk:8088/services/collector/event",
    ),
    splunk_token: str | None = typer.Option(None, help="Splunk HEC token"),
    splunk_index: str | None = typer.Option(None, help="Splunk index (optional)"),
    splunk_sourcetype: str | None = typer.Option("noisegraph", help="Splunk sourcetype"),
    # Datadog Logs
    dd_api_key: str | None = typer.Option(None, help="Datadog API key"),
    dd_site: str | None = typer.Option("datadoghq.com", help="Datadog site (datadoghq.com, datadoghq.eu, us3.datadoghq.com, ... )"),
    dd_service: str | None = typer.Option(None, help="Datadog service tag"),
    dd_source: str | None = typer.Option("noisegraph", help="Datadog source tag"),
    dd_tags: str | None = typer.Option(None, help="Additional Datadog tags, e.g. env:dev,team:soc"),
    forward_suppressed: bool = typer.Option(
        False,
        help="Forward suppressed decisions to external sinks (default: only kept)",
    ),
):
    emitters = _build_emitters(
        emit,
        jsonl_path=jsonl_path,
        splunk_hec_url=splunk_hec_url,
        splunk_token=splunk_token,
        splunk_index=splunk_index,
        splunk_sourcetype=splunk_sourcetype,
        dd_api_key=dd_api_key,
        dd_site=dd_site,
        dd_service=dd_service,
        dd_source=dd_source,
        dd_tags=dd_tags,
        only_keep=not forward_suppressed,
    )

    def _batch_url(url: str) -> str:
        if url.endswith("/ingest"):
            return url + "/batch"
        return url.rstrip("/") + "/ingest/batch"

    def _send_batch(client: httpx.Client, batch: list[str]) -> list[dict]:
        if not batch:
            return []
        if batch_size <= 1:
            d = []
            for line in batch:
                r = client.post(engine_url, json={"message": line, "source": source, "stream": stream})
                r.raise_for_status()
                d.append(r.json())
            return d
        payload = {"events": [{"message": line, "source": source, "stream": stream} for line in batch]}
        r = client.post(_batch_url(engine_url), json=payload)
        r.raise_for_status()
        return r.json().get("items", [])

    batch: list[str] = []
    last_send = 0.0
    policy_overrides = {"whitelist": 0, "blacklist": 0}
    with httpx.Client(timeout=10.0, http2=True) as client:
        for line in follow_file(path, read_existing=read_existing):
            if not line.strip():
                continue
            batch.append(line)
            now = time.time()
            if len(batch) >= max(1, batch_size) or (batch and (now - last_send) >= batch_interval):
                decisions = _send_batch(client, batch)
                for d in decisions:
                    for em in emitters:
                        em.emit(d)
                    po = d.get("policy_overridden")
                    if po in policy_overrides:
                        policy_overrides[po] += 1
                batch.clear()
                last_send = now
                if sum(policy_overrides.values()) > 0:
                    typer.echo(f"policy overrides: {policy_overrides}")

@ship.command("stdin")
def ship_stdin(
    source: str = typer.Option("mac.local", help="Source/host label"),
    stream: str = typer.Option("stdin", help="Stream label"),
    engine_url: str = typer.Option("http://127.0.0.1:8099/ingest", help="Engine ingest URL"),
    batch_size: int = typer.Option(1, help="Batch size for ingest (1=disable)"),
    batch_interval: float = typer.Option(0.5, help="Max seconds to wait before sending a batch"),
    emit: list[str] = typer.Option(
        ["console"],
        "--emit",
        "-e",
        help="Emit decisions to sinks. Repeatable. Values: console, jsonl, splunk, datadog",
    ),
    jsonl_path: Path | None = typer.Option(None, help="Required when --emit jsonl"),
    # Splunk HEC
    splunk_hec_url: str | None = typer.Option(
        None,
        help="Splunk HEC base URL or event endpoint, e.g. https://splunk:8088 or https://splunk:8088/services/collector/event",
    ),
    splunk_token: str | None = typer.Option(None, help="Splunk HEC token"),
    splunk_index: str | None = typer.Option(None, help="Splunk index (optional)"),
    splunk_sourcetype: str | None = typer.Option("noisegraph", help="Splunk sourcetype"),
    # Datadog Logs
    dd_api_key: str | None = typer.Option(None, help="Datadog API key"),
    dd_site: str | None = typer.Option("datadoghq.com", help="Datadog site (datadoghq.com, datadoghq.eu, us3.datadoghq.com, ... )"),
    dd_service: str | None = typer.Option(None, help="Datadog service tag"),
    dd_source: str | None = typer.Option("noisegraph", help="Datadog source tag"),
    dd_tags: str | None = typer.Option(None, help="Additional Datadog tags, e.g. env:dev,team:soc"),
    forward_suppressed: bool = typer.Option(
        False,
        help="Forward suppressed decisions to external sinks (default: only kept)",
    ),
):
    emitters = _build_emitters(
        emit,
        jsonl_path=jsonl_path,
        splunk_hec_url=splunk_hec_url,
        splunk_token=splunk_token,
        splunk_index=splunk_index,
        splunk_sourcetype=splunk_sourcetype,
        dd_api_key=dd_api_key,
        dd_site=dd_site,
        dd_service=dd_service,
        dd_source=dd_source,
        dd_tags=dd_tags,
        only_keep=not forward_suppressed,
    )
    def _batch_url(url: str) -> str:
        if url.endswith("/ingest"):
            return url + "/batch"
        return url.rstrip("/") + "/ingest/batch"

    def _send_batch(client: httpx.Client, batch: list[str]) -> list[dict]:
        if not batch:
            return []
        if batch_size <= 1:
            d = []
            for line in batch:
                r = client.post(engine_url, json={"message": line, "source": source, "stream": stream})
                r.raise_for_status()
                d.append(r.json())
            return d
        payload = {"events": [{"message": line, "source": source, "stream": stream} for line in batch]}
        r = client.post(_batch_url(engine_url), json=payload)
        r.raise_for_status()
        return r.json().get("items", [])

    batch: list[str] = []
    last_send = 0.0
    policy_overrides = {"whitelist": 0, "blacklist": 0}
    with httpx.Client(timeout=10.0, http2=True) as client:
        for line in read_stdin():
            if not line.strip():
                continue
            batch.append(line)
            now = time.time()
            if len(batch) >= max(1, batch_size) or (batch and (now - last_send) >= batch_interval):
                decisions = _send_batch(client, batch)
                for d in decisions:
                    for em in emitters:
                        em.emit(d)
                    po = d.get("policy_overridden")
                    if po in policy_overrides:
                        policy_overrides[po] += 1
                batch.clear()
                last_send = now
                if sum(policy_overrides.values()) > 0:
                    typer.echo(f"policy overrides: {policy_overrides}")
