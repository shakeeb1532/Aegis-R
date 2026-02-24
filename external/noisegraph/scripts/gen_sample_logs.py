from __future__ import annotations
import argparse, random
from datetime import datetime, timezone, timedelta

AUTH_FAIL = [
    "Failed password for {user} from {ip} port {port} ssh2",
    "Invalid user {user} from {ip} port {port}",
]
NOISE = [
    "Healthcheck OK for service={svc} latency_ms={ms}",
    "Cron job finished name={job} duration_ms={ms}",
    "Disk cleanup completed freed_mb={mb}",
    "Cache miss key={key} shard={shard}",
    "TLS handshake completed peer={ip}",
]
SERVICES = ["api", "worker", "gateway", "db", "auth"]
USERS = ["admin", "root", "shakeeb", "deploy", "service"]
JOBS = ["backup", "rotate", "sync", "gc"]
KEYS = ["user:123", "session:abc", "token:xyz", "cfg:prod"]

def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--lines", type=int, default=1000)
    args = ap.parse_args()

    out = []
    t = datetime.now(timezone.utc) - timedelta(minutes=5)
    for _ in range(args.lines):
        t = t + timedelta(seconds=random.randint(1, 4))
        if random.random() < 0.08:
            msg = random.choice(AUTH_FAIL).format(
                user=random.choice(USERS),
                ip=rand_ip(),
                port=random.randint(2000, 65000),
            )
        else:
            msg = random.choice(NOISE).format(
                svc=random.choice(SERVICES),
                ms=random.randint(1, 400),
                job=random.choice(JOBS),
                mb=random.randint(10, 500),
                key=random.choice(KEYS),
                shard=random.randint(1, 16),
                ip=rand_ip(),
            )
        out.append(f"{t.isoformat()}Z {msg}")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print(f"Wrote {len(out)} lines to {args.out}")

if __name__ == "__main__":
    main()
