"""
Seed script — loads 10,000 realistic sample events into SentinelSIEM.

Usage:
    python scripts/seed_demo_data.py --url http://localhost:8000 --count 10000
"""

import argparse
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

HOSTS = ["webserver01", "dbserver02", "dc01", "fw01", "app03", "vpn01", "k8s-node1"]
SOURCETYPES = ["syslog", "cef", "json"]
ACTIONS = ["failed", "success", "blocked", "allowed", "created", "deleted"]
USERS = ["alice", "bob", "charlie", "david", "root", "admin", "svc_backup"]
IPS = [f"192.168.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(30)]
EXTERNAL_IPS = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]

RAW_TEMPLATES = [
    "Jan 10 {time} {host} sshd[{pid}]: Failed password for {user} from {ip} port 22",
    "Jan 10 {time} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port 22",
    "Jan 10 {time} {host} sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash",
    "CEF:0|Cisco|ASA|9.8|106001|TCP connection denied|3|src={src_ip} dst={dst_ip} spt={spt} dpt={dpt} act=blocked",
    '{{"ts":"{ts}","event":"login","user":"{user}","src_ip":"{ip}","outcome":"{action}"}}',
    "Jan 10 {time} {host} kernel: audit: type=1106 audit({ts}): pid={pid} uid=0 subj=unconfined_u",
]


def make_event() -> dict:
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    src_ip = random.choice(IPS + EXTERNAL_IPS)
    dst_ip = random.choice(IPS)
    action = random.choice(ACTIONS)
    pid = random.randint(1000, 65535)
    spt = random.randint(1024, 65535)
    dpt = random.choice([22, 80, 443, 3389, 5432, 6379])
    ts_dt = datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 1440))
    ts_str = ts_dt.strftime("%H:%M:%S")
    ts_iso = ts_dt.isoformat()

    raw = random.choice(RAW_TEMPLATES).format(
        host=host, user=user, ip=src_ip, src_ip=src_ip, dst_ip=dst_ip,
        pid=pid, time=ts_str, ts=ts_iso, action=action, spt=spt, dpt=dpt,
    )
    sourcetype = "syslog"
    if raw.startswith("CEF"):
        sourcetype = "cef"
    elif raw.startswith("{"):
        sourcetype = "json"

    return {
        "raw": raw,
        "index": random.choice(["auth", "firewall", "system", "network"]),
        "sourcetype": sourcetype,
        "host": host,
        "ts": ts_dt.isoformat(),
    }


def main():
    parser = argparse.ArgumentParser(description="Seed SentinelSIEM with demo events")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--count", type=int, default=10_000)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="SentinelAdmin@2024")
    args = parser.parse_args()

    with httpx.Client(base_url=args.url, timeout=30) as client:
        # Login
        r = client.post("/auth/login", json={"username": args.username, "password": args.password})
        if r.status_code != 200:
            print(f"Login failed: {r.text}")
            sys.exit(1)
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"Logged in as {args.username}")

        # Seed in batches
        total = 0
        batch_count = (args.count + args.batch_size - 1) // args.batch_size
        for i in range(batch_count):
            batch = [make_event() for _ in range(min(args.batch_size, args.count - total))]
            r = client.post("/events/ingest/batch", json={"events": batch}, headers=headers)
            if r.status_code == 201:
                ingested = r.json()["ingested"]
                total += ingested
                print(f"  Batch {i+1}/{batch_count}: +{ingested} events (total: {total})")
            else:
                print(f"  Batch {i+1} failed: {r.status_code} {r.text}")
            time.sleep(0.05)  # be gentle

    print(f"\nDone. Seeded {total} events.")


if __name__ == "__main__":
    main()
