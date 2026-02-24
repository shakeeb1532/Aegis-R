from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

USERS = ["admin", "root", "svc-api", "svc-db", "deploy", "backup", "analyst", "svc-billing", "svc-cache", "ops"]
SERVICES = ["api", "worker", "db", "ssh", "nginx", "redis", "kubelet", "billing", "search"]
HOSTS = [f"host-{i:02d}" for i in range(1, 31)]
IPS = [
    "10.0.0.5", "10.0.1.7", "10.0.2.9", "10.0.3.11",
    "172.16.1.10", "172.16.2.12", "172.16.3.14",
    "192.168.1.22", "192.168.1.23", "192.168.1.24",
    "8.8.8.8", "1.1.1.1", "9.9.9.9",
]
NAMESPACES = ["prod", "staging", "dev"]
USER_AGENTS = ["Mozilla/5.0", "curl/7.88.1", "kube-probe/1.27", "PostmanRuntime/7.35.0"]
ERROR_CODES = ["ECONNREFUSED", "ETIMEOUT", "EPIPE", "EHOSTUNREACH", "ECONNRESET"]
HTTP_STATUS = [200, 200, 200, 301, 404, 500, 502, 503]
TENANTS = [f"tenant-{i:03d}" for i in range(1, 41)]
SESSION_PREFIX = ["sess", "sid", "token"]
EXTRA_USERS = [f"user{i:03d}" for i in range(1, 200)]
EXTRA_IPS = [f"203.0.113.{i}" for i in range(1, 200)]


def ts(base: datetime, jitter_ms: int) -> str:
    return (base + timedelta(milliseconds=random.randint(0, jitter_ms))).isoformat()


def auth_fail(base: datetime) -> str:
    u = random.choice(USERS)
    ip = random.choice(IPS)
    port = random.randint(2000, 65000)
    return f"{ts(base, 500)} Failed password for {u} from {ip} port {port} ssh2"


def healthcheck(base: datetime) -> str:
    svc = random.choice(SERVICES)
    ms = random.randint(4, 120)
    return f"{ts(base, 200)} Healthcheck OK service={svc} latency_ms={ms}"


def nginx_access(base: datetime) -> str:
    ip = random.choice(IPS)
    path = random.choice(["/login", "/api/v1/users", "/healthz", "/metrics", "/admin"])
    status = random.choice(HTTP_STATUS)
    ms = random.randint(2, 800)
    ua = random.choice(USER_AGENTS)
    return f"{ts(base, 500)} nginx access ip={ip} path={path} status={status} latency_ms={ms} ua={ua}"


def kubelet_event(base: datetime) -> str:
    ns = random.choice(NAMESPACES)
    pod = f"pod-{random.randint(1000,9999)}"
    return f"{ts(base, 200)} kubelet pod={pod} ns={ns} status=Running"


def app_error(base: datetime) -> str:
    svc = random.choice(SERVICES)
    code = random.choice(ERROR_CODES)
    ctx = random.choice(["db", "cache", "queue", "auth"])
    return f"{ts(base, 500)} ERROR service={svc} msg='{ctx} connection refused' code={code}"


def privilege_escalation(base: datetime) -> str:
    u = random.choice(["admin", "root"])
    return f"{ts(base, 200)} sudo: {u} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"


def anomaly_burst(base: datetime) -> str:
    ip = random.choice(IPS)
    port = random.choice([4444, 5555, 6666, 7777])
    sig = random.choice(["scan", "bruteforce", "exfil", "c2"])
    return f"{ts(base, 100)} ALERT {sig} traffic from {ip} to port {port}"


def _emit(out, fmt: str, obj: dict, message: str) -> None:
    if fmt == "jsonl":
        obj.setdefault("message", message)
        out.write(json.dumps(obj) + "\n")
    else:
        out.write(message + "\n")


def _rotate(val_list: list[str], step: int) -> str:
    return val_list[step % len(val_list)]


def _session_id(step: int) -> str:
    return f"{random.choice(SESSION_PREFIX)}-{step:06d}-{random.randint(1000,9999)}"


def _tenant(step: int) -> str:
    return TENANTS[step % len(TENANTS)]


def _service_template(svc: str, base: datetime) -> str:
    if svc in {"api", "worker", "billing", "search"}:
        op = random.choice(["GET", "POST", "PUT", "DELETE"])
        path = random.choice(["/v1/orders", "/v1/users", "/v1/search", "/v1/payments"])
        ms = random.randint(5, 1500)
        return f"{ts(base, 200)} {svc} {op} {path} status={random.choice(HTTP_STATUS)} latency_ms={ms}"
    if svc == "db":
        q = random.choice(["SELECT", "UPDATE", "INSERT", "DELETE"])
        ms = random.randint(1, 500)
        return f"{ts(base, 200)} db query={q} rows={random.randint(1,200)} latency_ms={ms}"
    if svc == "redis":
        cmd = random.choice(["GET", "SET", "HGET", "HSET"])
        return f"{ts(base, 100)} redis cmd={cmd} key=key{random.randint(1,5000)}"
    if svc == "ssh":
        return auth_fail(base)
    return healthcheck(base)


def generate(n: int, out: Path, profile: str, fmt: str) -> None:
    base = datetime.now(timezone.utc)
    config_epoch = 0
    burst_left = 0
    tenant_burst_left = 0
    tenant_burst = None
    churn_left = 0
    rolling_left = 0
    rolling_rev = 0
    rolling_services: list[str] = []
    with out.open("w") as f:
        for i in range(n):
            r = random.random()
            # Periodic config changes: new template tokens every 5k lines.
            if i % 5000 == 0 and i > 0:
                config_epoch += 1

            # Burst anomalies: occasional short spikes with varying templates.
            if burst_left > 0:
                burst_left -= 1
                r = 0.999  # force anomaly path
            elif random.random() < 0.01:
                burst_left = random.randint(20, 80)

            # Rolling deploys: change templates across multiple services at once.
            if rolling_left > 0:
                rolling_left -= 1
            elif random.random() < 0.005:
                rolling_left = random.randint(200, 600)
                rolling_rev += 1
                rolling_services = random.sample(SERVICES, k=min(3, len(SERVICES)))

            # User/IP churn bursts: introduce new entities rapidly.
            if churn_left > 0:
                churn_left -= 1
            elif random.random() < 0.01:
                churn_left = random.randint(100, 300)

            host = _rotate(HOSTS, i)
            svc = _rotate(SERVICES, i // 3)
            if churn_left > 0:
                user = random.choice(USERS + EXTRA_USERS)
                ip = random.choice(IPS + EXTRA_IPS)
            else:
                user = _rotate(USERS, i // 7)
                ip = _rotate(IPS, i // 5)
            tenant = _tenant(i)
            session = _session_id(i)

            # Multi-tenant bursts: sudden activity spikes for one tenant.
            if tenant_burst_left > 0:
                tenant_burst_left -= 1
                tenant = tenant_burst or tenant
            elif random.random() < 0.01:
                tenant_burst_left = random.randint(50, 150)
                tenant_burst = _tenant(i + random.randint(1, 10))
            if profile == "webapp":
                if r < 0.55:
                    line = nginx_access(base)
                elif r < 0.85:
                    line = _service_template(svc, base)
                elif r < 0.97:
                    line = app_error(base)
                else:
                    line = anomaly_burst(base)
                # Config change adds version token to template.
                if config_epoch > 0:
                    line = f"{line} build=v{config_epoch}"
                if rolling_left > 0 and svc in rolling_services:
                    line = f"{line} deploy=rev{rolling_rev}"
                line = f"{line} tenant={tenant} session={session}"
                _emit(f, fmt, {"source": host, "stream": "webapp", "service": svc, "user": user}, line)
            elif profile == "kubernetes":
                if r < 0.6:
                    line = kubelet_event(base)
                elif r < 0.9:
                    line = _service_template(svc, base)
                else:
                    line = app_error(base)
                obj = {
                    "source": host,
                    "stream": "stdout",
                    "kubernetes": {
                        "namespace": random.choice(NAMESPACES),
                        "pod": f"pod-{random.randint(1000,9999)}",
                        "container": svc,
                        "node": host,
                    },
                }
                if config_epoch > 0:
                    line = f"{line} deploy=rev{config_epoch}"
                if rolling_left > 0 and svc in rolling_services:
                    line = f"{line} rolling=rev{rolling_rev}"
                line = f"{line} tenant={tenant} session={session}"
                _emit(f, fmt, obj, line)
            elif profile == "windows_auth":
                if r < 0.7:
                    msg = f"{ts(base, 100)} EventID=4625 Failed Logon User={user} IP={ip} Workstation={host}"
                elif r < 0.95:
                    msg = f"{ts(base, 100)} EventID=4624 Successful Logon User={user} IP={ip} Workstation={host}"
                else:
                    msg = f"{ts(base, 100)} EventID=4672 Special privileges assigned User={user} Workstation={host}"
                if config_epoch > 0:
                    msg = f"{msg} policy=rev{config_epoch}"
                if rolling_left > 0:
                    msg = f"{msg} gpo=rev{rolling_rev}"
                msg = f"{msg} session={session}"
                _emit(f, fmt, {"source": host, "stream": "security"}, msg)
            elif profile == "cloudtrail":
                if r < 0.8:
                    event = "ConsoleLogin"
                elif r < 0.95:
                    event = "AssumeRole"
                else:
                    event = "CreateUser"
                msg = f"{ts(base, 100)} AWS {event} user={user} sourceIp={ip}"
                obj = {
                    "eventVersion": "1.09",
                    "eventSource": "signin.amazonaws.com",
                    "eventName": event,
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": ip,
                    "userIdentity": {"type": "IAMUser", "userName": user},
                    "eventTime": ts(base, 0),
                    "source": host,
                }
                if config_epoch > 0:
                    msg = f"{msg} session=rev{config_epoch}"
                if rolling_left > 0:
                    msg = f"{msg} deploy=rev{rolling_rev}"
                msg = f"{msg} tenant={tenant}"
                _emit(f, fmt, obj, msg)
            elif profile == "datadog":
                line = nginx_access(base) if r < 0.6 else _service_template(svc, base)
                obj = {
                    "ddsource": "nginx" if "nginx" in line else "app",
                    "service": "web",
                    "host": host,
                    "ddtags": f"env:{random.choice(NAMESPACES)},team:soc",
                    "timestamp": ts(base, 0),
                    "source": host,
                    "stream": "datadog",
                }
                if config_epoch > 0:
                    line = f"{line} version=v{config_epoch}"
                if rolling_left > 0 and svc in rolling_services:
                    line = f"{line} deploy=rev{rolling_rev}"
                line = f"{line} tenant={tenant} session={session}"
                _emit(f, fmt, obj, line)
            elif profile == "splunk":
                line = auth_fail(base) if r < 0.6 else _service_template(svc, base)
                obj = {
                    "time": base.timestamp(),
                    "host": host,
                    "sourcetype": "noisegraph",
                    "event": {"message": line, "source": host, "stream": "splunk"},
                    "source": host,
                }
                if config_epoch > 0:
                    line = f"{line} rev={config_epoch}"
                if rolling_left > 0 and svc in rolling_services:
                    line = f"{line} deploy=rev{rolling_rev}"
                line = f"{line} tenant={tenant} session={session}"
                _emit(f, fmt, obj, line)
            elif profile == "logzio":
                line = app_error(base) if r < 0.1 else nginx_access(base)
                obj = {
                    "@timestamp": ts(base, 0),
                    "type": "logzio",
                    "host": host,
                    "tags": [f"env:{random.choice(NAMESPACES)}", "team:soc"],
                    "source": host,
                    "stream": "logzio",
                }
                if config_epoch > 0:
                    line = f"{line} cfg={config_epoch}"
                if rolling_left > 0 and svc in rolling_services:
                    line = f"{line} deploy=rev{rolling_rev}"
                line = f"{line} tenant={tenant} session={session}"
                _emit(f, fmt, obj, line)
            else:
                if r < 0.45:
                    line = auth_fail(base)
                elif r < 0.75:
                    line = healthcheck(base)
                elif r < 0.90:
                    line = nginx_access(base)
                elif r < 0.95:
                    line = kubelet_event(base)
                elif r < 0.985:
                    line = app_error(base)
                elif r < 0.995:
                    line = privilege_escalation(base)
                else:
                    line = anomaly_burst(base)
                if config_epoch > 0:
                    line = f"{line} build=v{config_epoch}"
                line = f"{line} tenant={tenant} session={session}"
                _emit(f, fmt, {"source": host, "stream": "default", "service": svc, "user": user}, line)
            base += timedelta(milliseconds=random.randint(10, 200))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("logs/realistic.log"))
    ap.add_argument("--lines", type=int, default=50000)
    ap.add_argument(
        "--profile",
        choices=["default", "webapp", "kubernetes", "windows_auth", "cloudtrail", "datadog", "splunk", "logzio"],
        default="default",
    )
    ap.add_argument("--format", choices=["plain", "jsonl"], default="plain")
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    generate(args.lines, args.out, args.profile, args.format)


if __name__ == "__main__":
    main()
