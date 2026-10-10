#!/usr/bin/env python3
"""pingmon: monitor continuo de latencia desde la oficina hacia regiones de AWS.

Mide el RTT de conexión TCP (SYN -> SYN/ACK) a endpoints regionales de AWS y al
servidor RTMP, más ICMP a unos objetivos de control (router, internet) para
distinguir si el lag viene de la red de la oficina o del camino hacia AWS.

Uso:
  python3 pingmon.py run         # sondea + sirve el dashboard (http://127.0.0.1:8787)
  python3 pingmon.py probe       # solo sondea
  python3 pingmon.py serve       # solo dashboard
  python3 pingmon.py report [--window 24h]
  python3 pingmon.py install     # arranque automático con launchd (macOS)
  python3 pingmon.py uninstall

Solo librería estándar (Python >= 3.8).
"""
import argparse
import json
import math
import os
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "config.json")
DATA_DIR = os.path.join(BASE, "data")
DB_PATH = os.path.join(DATA_DIR, "pingmon.db")
DASHBOARD = os.path.join(BASE, "dashboard.html")
LAUNCHD_LABEL = "com.kerma.pingmon"
PLIST_PATH = os.path.expanduser("~/Library/LaunchAgents/%s.plist" % LAUNCHD_LABEL)

PLACEHOLDER_HOSTS = ("CAMBIAR", "")
DNS_TTL = 300

# Objetivos de auditoría que se añaden aunque la config.json instalada sea antigua.
AUTO_TARGETS = [
    # Pausas del propio Mac durante cada ronda: separa "se congeló el Mac" de "se paró la red".
    {"id": "self", "name": "Este Mac (pausas)", "kind": "self", "method": "self", "host": "local"},
    # El mismo router y el mismo 1.1.1.1 por TCP: si TCP no pierde y el ping sí, el firewall limita ICMP.
    {"id": "gateway-tcp", "name": "Router oficina (TCP)", "kind": "control", "method": "tcp-auto", "host": "auto"},
    {"id": "internet-tcp", "name": "Internet (1.1.1.1 TCP)", "kind": "control", "method": "tcp", "host": "1.1.1.1", "port": 443},
]
AUTO_PORTS = (443, 80, 53, 22, 8443, 8080)

AUDIT_DEFAULTS = {
    "egress_every_seconds": 120,       # IP pública de salida y proveedor
    "trace_every_seconds": 900,        # traceroute
    "trace_targets": ["server", "mx-central-1"],
}


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    targets = []
    for t in cfg["targets"]:
        host = t.get("host", "")
        if any(host.startswith(p) for p in PLACEHOLDER_HOSTS if p) or not host:
            continue  # objetivo sin configurar (p. ej. servidor RTMP pendiente)
        targets.append(t)
    have = {t["id"] for t in cfg["targets"]}
    for t in AUTO_TARGETS:
        if t["id"] not in have:
            targets.append(dict(t, auto=True))
    cfg["active_targets"] = targets
    cfg["audit"] = dict(AUDIT_DEFAULTS, **cfg.get("audit", {}))
    return cfg


# --------------------------------------------------------------------------- db

def db_connect():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS samples ("
        " ts REAL NOT NULL, target TEXT NOT NULL, rtt_ms REAL, ip TEXT)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS samples_target_ts ON samples(target, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts)")
    conn.execute("CREATE TABLE IF NOT EXISTS egress ("
                 " ts REAL NOT NULL, ip TEXT, colo TEXT, asn TEXT, asname TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS traces ("
                 " ts REAL NOT NULL, target TEXT NOT NULL, ip TEXT, hops TEXT)")
    return conn


# ----------------------------------------------------------------------- probes

_dns_cache = {}


def resolve(host):
    """Resuelve fuera de la medición, para que el tiempo de DNS no contamine el RTT."""
    now = time.time()
    hit = _dns_cache.get(host)
    if hit and now - hit[1] < DNS_TTL:
        return hit[0]
    if host == "auto":
        ip = default_gateway()
    else:
        ip = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    _dns_cache[host] = (ip, now)
    return ip


def default_gateway():
    out = subprocess.run(["/sbin/route", "-n", "get", "default"],
                         capture_output=True, text=True, timeout=5).stdout
    m = re.search(r"gateway:\s*(\S+)", out)
    if not m:
        raise RuntimeError("no se encontró gateway por defecto")
    return m.group(1)


def probe_tcp(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        t0 = time.perf_counter()
        s.connect((ip, port))
        return (time.perf_counter() - t0) * 1000
    except ConnectionRefusedError:
        # Un RST también es una respuesta del host: el RTT es válido.
        return (time.perf_counter() - t0) * 1000
    except OSError:
        return None
    finally:
        s.close()


_auto_port = {}  # ip -> (puerto que responde o None, ts del último escaneo)


def probe_tcp_auto(ip, timeout):
    """TCP a un equipo de la red (router/firewall) probando puertos hasta que uno conteste.

    Vale tanto SYN/ACK como RST: los dos son respuesta del equipo.
    """
    port, scanned = _auto_port.get(ip, (None, 0))
    if port is not None:
        rtt = probe_tcp(ip, port, timeout)
        if rtt is not None or time.time() - scanned < 600:
            return rtt
    elif time.time() - scanned < 600:
        return None
    for p in AUTO_PORTS:
        rtt = probe_tcp(ip, p, 0.3)
        if rtt is not None:
            _auto_port[ip] = (p, time.time())
            return rtt
    _auto_port[ip] = (None, time.time())
    return None


def watch_pauses(done, limit):
    """Mide la mayor pausa del propio Mac mientras dura la ronda.

    Duerme a intervalos de 5 ms; si una vuelta tarda mucho más, el Mac (CPU,
    reposo, planificador) estuvo parado y cualquier retraso de esa ronda es suyo.
    """
    worst, last, end = 0.0, time.perf_counter(), time.perf_counter() + limit
    while not done.is_set() and time.perf_counter() < end:
        time.sleep(0.005)
        now = time.perf_counter()
        worst = max(worst, (now - last) * 1000 - 5)
        last = now
    return max(worst, 0.0)


PING_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


def probe_icmp(ip, timeout):
    wait_ms = str(int(timeout * 1000))
    try:
        out = subprocess.run(["/sbin/ping", "-n", "-c", "1", "-W", wait_ms, ip],
                             capture_output=True, text=True, timeout=timeout + 2).stdout
    except subprocess.TimeoutExpired:
        return None
    m = PING_RE.search(out)
    return float(m.group(1)) if m else None


def probe_target(t, timeout):
    if t.get("method") == "self":
        return None, None, None  # se mide aparte, en watch_pauses
    try:
        ip = resolve(t["host"])
    except Exception as e:  # DNS caído cuenta como pérdida
        return None, None, str(e)
    if t.get("method") == "icmp":
        rtt = probe_icmp(ip, timeout)
    elif t.get("method") == "tcp-auto":
        rtt = probe_tcp_auto(ip, timeout)
    else:
        rtt = probe_tcp(ip, int(t.get("port", 443)), timeout)
    return rtt, ip, None


def probe_loop(stop=None):
    cfg = load_config()
    targets = cfg["active_targets"]
    interval = float(cfg.get("interval_seconds", 10))
    timeout = float(cfg.get("timeout_seconds", 1.0))
    retention = float(cfg.get("retention_days", 30)) * 86400
    conn = db_connect()
    log("sondeando %d objetivos cada %.0fs: %s" % (
        len(targets), interval, ", ".join(t["id"] for t in targets)))
    skipped = [t["id"] for t in cfg["targets"] if t not in targets]
    if skipped:
        log("sin configurar (se ignoran): %s" % ", ".join(skipped))

    for name, fn in (("salida", egress_loop), ("traceroute", trace_loop)):
        threading.Thread(target=_audit_thread, args=(name, fn, cfg, stop), daemon=True).start()

    pool = ThreadPoolExecutor(max_workers=max(1, len(targets)) + 1)
    next_tick = time.time()
    last_prune = 0
    while not (stop and stop.is_set()):
        ts = time.time()
        done = threading.Event()
        pauses = pool.submit(watch_pauses, done, timeout + 1.5)
        results = list(pool.map(lambda t: probe_target(t, timeout), targets))
        done.set()
        pause_ms = pauses.result()
        rows = []
        for t, (rtt, ip, err) in zip(targets, results):
            if t.get("method") == "self":
                rtt = pause_ms
            rows.append((ts, t["id"], rtt, ip))
            if err:
                log("%s: %s" % (t["id"], err))
        try:
            conn.executemany("INSERT INTO samples VALUES (?,?,?,?)", rows)
            conn.commit()
            if ts - last_prune > 3600:
                for table in ("samples", "egress", "traces"):
                    conn.execute("DELETE FROM %s WHERE ts < ?" % table, (ts - retention,))
                conn.commit()
                last_prune = ts
        except sqlite3.Error as e:
            log("error guardando muestras: %s" % e)
        next_tick += interval
        delay = next_tick - time.time()
        if delay < 0:  # nos hemos retrasado (p. ej. el Mac durmió): re-sincroniza
            next_tick = time.time()
            delay = 0
        if stop:
            stop.wait(delay)
        else:
            time.sleep(delay)


def _audit_thread(name, fn, cfg, stop):
    # Un fallo de la auditoría nunca debe parar las mediciones de latencia.
    while not (stop and stop.is_set()):
        try:
            fn(cfg, stop)
        except Exception as e:
            log("auditoría (%s): %r" % (name, e))
        time.sleep(60)


def _wait(stop, seconds):
    if stop:
        stop.wait(seconds)
    else:
        time.sleep(seconds)


def egress_loop(cfg, stop):
    """IP pública por la que sale la oficina y su proveedor (AS)."""
    import urllib.request
    conn = db_connect()
    every = float(cfg["audit"]["egress_every_seconds"])
    last_ip, asn, asname = None, None, None
    while not (stop and stop.is_set()):
        ip = colo = None
        try:
            body = urllib.request.urlopen("https://1.1.1.1/cdn-cgi/trace", timeout=10).read().decode()
            kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
            ip, colo = kv.get("ip"), kv.get("colo")
        except Exception:
            pass  # sin respuesta: se guarda como fila vacía (salida caída)
        if ip and ip != last_ip:
            asn, asname = whois_as(ip)
            last_ip = ip
        conn.execute("INSERT INTO egress VALUES (?,?,?,?,?)",
                     (time.time(), ip, colo, asn if ip else None, asname if ip else None))
        conn.commit()
        _wait(stop, every)


def whois_as(ip):
    """Proveedor de una IP pública (Team Cymru)."""
    try:
        out = subprocess.run(["/usr/bin/whois", "-h", "whois.cymru.com", " -v " + ip],
                             capture_output=True, text=True, timeout=20).stdout
        cols = [c.strip() for c in out.strip().splitlines()[-1].split("|")]
        asn = "AS" + cols[0]
        name = cols[-1]
        if name.startswith(asn + " - "):  # Cymru a veces repite el número delante del nombre
            name = name[len(asn) + 3:]
        return asn, name
    except Exception:
        return None, None


HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MS_RE = re.compile(r"([\d.]+)\s*ms")


def parse_traceroute(out):
    hops = []
    for line in out.splitlines():
        m = HOP_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        ips = IP_RE.findall(rest)
        ms = [float(x) for x in MS_RE.findall(rest)]
        hops.append([int(m.group(1)), ips[0] if ips else None, min(ms) if ms else None])
    return hops


def trace_loop(cfg, stop):
    conn = db_connect()
    every = float(cfg["audit"]["trace_every_seconds"])
    by_id = {t["id"]: t for t in cfg["active_targets"]}
    wanted = [by_id[i] for i in cfg["audit"]["trace_targets"] if i in by_id]
    while not (stop and stop.is_set()):
        for t in wanted:
            try:
                ip = resolve(t["host"])
                out = subprocess.run(["/usr/sbin/traceroute", "-n", "-q", "2", "-w", "1", "-m", "20", ip],
                                     capture_output=True, text=True, timeout=120).stdout
                conn.execute("INSERT INTO traces VALUES (?,?,?,?)",
                             (time.time(), t["id"], ip, json.dumps(parse_traceroute(out))))
                conn.commit()
            except Exception as e:
                log("traceroute %s: %r" % (t["id"], e))
        _wait(stop, every)


def _probe_or_die():
    # Si el sondeo muere, tumba el proceso para que launchd (KeepAlive) lo relance.
    try:
        probe_loop()
    except Exception as e:
        log("sondeo abortado: %r" % e)
    os._exit(1)


# -------------------------------------------------------------------- analytics

def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    k = max(0, min(len(sorted_vals) - 1, math.ceil(p / 100.0 * len(sorted_vals)) - 1))
    return sorted_vals[k]


def stats(rtts, total):
    ok = sorted(r for r in rtts if r is not None)
    jit = None
    seq = [r for r in rtts if r is not None]
    if len(seq) > 1:
        jit = sum(abs(a - b) for a, b in zip(seq, seq[1:])) / (len(seq) - 1)
    loss = (total - len(ok)) / total if total else None
    return {
        "n": total,
        "p50": pct(ok, 50), "p95": pct(ok, 95), "p99": pct(ok, 99),
        "min": ok[0] if ok else None, "max": ok[-1] if ok else None,
        "jitter": jit, "loss": loss,
    }


def score(s):
    """Menor es mejor. p95 + 2×jitter + 50 ms por cada 1 % de pérdida."""
    if s["p95"] is None:
        return None
    return s["p95"] + 2 * (s["jitter"] or 0) + 5000 * (s["loss"] or 0)


def parse_window(w):
    m = re.fullmatch(r"(\d+)([smhd]?)", str(w))
    if not m:
        raise ValueError("ventana inválida: %s" % w)
    mult = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    return int(m.group(1)) * mult


def elevated(b, base):
    """¿Este tramo está degradado respecto a lo normal del objetivo?"""
    if b["n"] < 3 or base is None:
        return False
    if b["loss"] is not None and b["loss"] >= 0.10:
        return True
    return b["p95"] is not None and b["p95"] > base + max(15.0, base)


def analyze(window_s):
    cfg = load_config()
    targets = cfg["active_targets"]
    interval = float(cfg.get("interval_seconds", 10))
    now = time.time()
    start = now - window_s
    bucket_s = max(interval * 6, window_s / 120.0)
    nb = int(window_s // bucket_s) + 1

    conn = db_connect()
    by_target = {t["id"]: [] for t in targets}
    for ts, tid, rtt in conn.execute(
            "SELECT ts, target, rtt_ms FROM samples WHERE ts >= ? ORDER BY ts", (start,)):
        if tid in by_target:
            by_target[tid].append((ts, rtt))
    conn.close()

    mac_pauses, net_stalls = classify_stalls(targets, by_target)
    if mac_pauses:  # solo se descartan las rondas en que el Mac estuvo parado
        for tid in by_target:
            by_target[tid] = [r for r in by_target[tid] if r[0] not in mac_pauses]

    summary, series, heat, buckets_raw = {}, {}, {}, {}
    for t in targets:
        rows = by_target[t["id"]]
        s = stats([r for _, r in rows], len(rows))
        s["score"] = score(s)
        summary[t["id"]] = s

        per_b = [[] for _ in range(nb)]
        per_h = [[] for _ in range(24)]
        for ts, rtt in rows:
            per_b[min(nb - 1, int((ts - start) // bucket_s))].append(rtt)
            per_h[time.localtime(ts).tm_hour].append(rtt)
        bstats = [stats(v, len(v)) for v in per_b]
        buckets_raw[t["id"]] = bstats
        series[t["id"]] = {k: [b[k] for b in bstats] for k in ("p50", "p95", "max", "loss", "n")}
        heat[t["id"]] = [{"p95": h["p95"], "loss": h["loss"], "n": h["n"]}
                         for h in (stats(v, len(v)) for v in per_h)]

    return {
        "generated": now,
        "window": window_s,
        "interval": interval,
        "bucket": bucket_s,
        "start": start,
        "targets": [{k: t.get(k) for k in ("id", "name", "kind", "method", "host", "port")}
                    for t in targets],
        "unconfigured": [t["id"] for t in cfg["targets"] if t not in targets],
        "summary": summary,
        "series": series,
        "heatmap": heat,
        "verdict": verdict(targets, summary, buckets_raw, nb),
        "audit": audit(targets, summary, start, mac_pauses, net_stalls),
    }


MAC_PAUSE_MS = 20


def classify_stalls(targets, by_target):
    """Separa las pausas del propio Mac de los parones de la red.

    Parón simultáneo: varios destinos con latencias normales distintas (p. ej. 30 y
    80 ms) contestan a la vez con casi el mismo RTT (±2 ms) y por encima de lo normal.
    Eso solo pasa si algo retuvo las respuestas y las soltó de golpe: o el Mac estuvo
    parado, o un equipo de la red (firewall, switch). La sonda "self" mide las pausas
    del Mac en esa misma ronda y decide cuál de las dos fue.

    Devuelve (rondas con el Mac parado, [(ts, retraso añadido ms, verificado)]).
    """
    pauses = {ts: v for ts, v in by_target.get("self", [])}
    mac = {ts for ts, v in pauses.items() if v is None or v > MAC_PAUSE_MS}
    tcp = [t["id"] for t in targets if t.get("method", "tcp") in ("tcp", "tcp-auto")]
    base = {}
    for tid in tcp:
        base[tid] = pct(sorted(r for _, r in by_target[tid] if r is not None), 50)
    rounds = {}
    for tid in tcp:
        for ts, rtt in by_target[tid]:
            if rtt is not None and base[tid]:
                rounds.setdefault(ts, []).append((rtt, base[tid]))
    net = []
    for ts, vals in sorted(rounds.items()):
        if len(vals) < 3 or ts in mac:
            continue
        rtts = [v for v, _ in vals]
        bases = [b for _, b in vals]
        if (max(rtts) - min(rtts) <= 2.0 and max(bases) - min(bases) >= 10
                and all(v > b + 15 for v, b in vals)):
            added = sorted(v - b for v, b in vals)[len(vals) // 2]
            net.append((ts, added, ts in pauses))
    return mac, net


def audit(targets, summary, start, mac_pauses, net_stalls):
    out = {"mac_pauses": len(mac_pauses)}

    # Parones simultáneos: cuántos, cuándo y si se repiten con un ritmo fijo.
    per_day, per_hour = {}, [0] * 24
    for ts, _, _ in net_stalls:
        lt = time.localtime(ts)
        day = time.strftime("%Y-%m-%d", lt)
        per_day[day] = per_day.get(day, 0) + 1
        per_hour[lt.tm_hour] += 1
    gaps = [b[0] - a[0] for a, b in zip(net_stalls, net_stalls[1:])]
    med = sorted(gaps)[len(gaps) // 2] if gaps else None
    regular = None
    if len(gaps) >= 5:
        near = sum(1 for g in gaps if abs(g - med) <= 0.15 * med)
        regular = near >= 0.5 * len(gaps)
    out["sync_stalls"] = {
        "count": len(net_stalls),
        "verified": sum(1 for _, _, v in net_stalls if v),
        "median_added_ms": sorted(a for _, a, _ in net_stalls)[len(net_stalls) // 2] if net_stalls else None,
        "median_gap_s": med,
        "regular": regular,
        "per_day": per_day,
        "per_hour": per_hour,
        "events": [[round(ts, 1), round(a, 1), v] for ts, a, v in net_stalls[-500:]],
    }

    # Mismo destino por ICMP y por TCP: si solo pierde el ping, el firewall lo está limitando.
    pairs = []
    for icmp, tcp in (("gateway", "gateway-tcp"), ("internet", "internet-tcp")):
        if icmp in summary and tcp in summary and summary[icmp]["n"] and summary[tcp]["n"]:
            pairs.append({"icmp": icmp, "tcp": tcp,
                          "icmp_loss": summary[icmp]["loss"], "tcp_loss": summary[tcp]["loss"]})
    out["icmp_vs_tcp"] = pairs

    conn = db_connect()
    # Línea de salida: cambios de IP pública, proveedor o PoP de Cloudflare.
    changes, prev, down = [], None, 0
    rows = conn.execute("SELECT ts, ip, colo, asn, asname FROM egress WHERE ts >= ? ORDER BY ts",
                        (start,)).fetchall()
    for ts, ip, colo, asn, asname in rows:
        if ip is None:
            down += 1
            continue
        key = (ip, colo)
        if key != prev:
            changes.append({"ts": ts, "ip": ip, "colo": colo, "asn": asn, "asname": asname})
            prev = key
    out["egress"] = {"checks": len(rows), "failed": down,
                     "current": changes[-1] if changes else None, "changes": changes[-50:]}

    # Rutas: último traceroute y cambios de camino (ignorando saltos que no contestan).
    paths = {}
    for (tid,) in conn.execute("SELECT DISTINCT target FROM traces WHERE ts >= ?", (start,)):
        traces = conn.execute("SELECT ts, ip, hops FROM traces WHERE target = ? AND ts >= ? ORDER BY ts",
                              (tid, start)).fetchall()
        changes, prev = [], None
        for ts, ip, hops in traces:
            sig = [h[1] for h in json.loads(hops) if h[1]]
            if prev is not None and sig != prev:
                changes.append({"ts": ts, "from": prev, "to": sig})
            prev = sig
        ts, ip, hops = traces[-1]
        paths[tid] = {"latest": {"ts": ts, "ip": ip, "hops": json.loads(hops)},
                      "count": len(traces), "changes": changes[-30:]}
    conn.close()
    out["paths"] = paths
    return out


def verdict(targets, summary, buckets, nb):
    ids = lambda kind: [t["id"] for t in targets if t["kind"] == kind and summary[t["id"]]["n"]]
    # Un servidor que no responde (puerto filtrado para esta máquina) no puede dar episodios.
    ignored_servers = [i for i in ids("server") if summary[i]["loss"] > 0.5]
    servers = [i for i in ids("server") if i not in ignored_servers]
    regions = ids("region")
    # Un control que casi nunca responde (router que filtra ICMP) no sirve de referencia.
    controls = [i for i in ids("control") if summary[i]["loss"] <= 0.5]
    ignored = [i for i in ids("control") if i not in controls]
    gw = [i for i in controls if i.startswith("gateway")]
    inet = [i for i in controls if not i.startswith("gateway")]
    aws_ref = servers or regions
    if not aws_ref:
        return {"state": "nodata", "episodes": 0, "ignored_servers": ignored_servers}

    def elev(tid, i):
        return elevated(buckets[tid][i], summary[tid]["p50"])

    episodes = local = lan = 0
    for i in range(nb):
        if servers:
            aws_bad = any(elev(s, i) for s in servers)
        else:
            active = [r for r in regions if buckets[r][i]["n"] >= 3]
            aws_bad = bool(active) and sum(elev(r, i) for r in active) * 2 >= len(active)
        if not aws_bad:
            continue
        episodes += 1
        gw_bad = any(elev(g, i) for g in gw)
        inet_bad = any(elev(c, i) for c in inet)
        if gw_bad or inet_bad:
            local += 1
        if gw_bad:
            lan += 1

    # Con pocas muestras el ranking es ruido: no se nombra "mejor región" hasta tener ~15 min.
    ranked = sorted((summary[r]["score"], r) for r in regions
                    if summary[r]["score"] is not None and summary[r]["n"] >= 90)
    out = {
        "episodes": episodes,
        "local": local,
        "lan": lan,
        "reference": "server" if servers else "regions",
        "controls": controls,
        "ignored_controls": ignored,
        "ignored_servers": ignored_servers,
        "best_region": ranked[0][1] if ranked else None,
        "ranking": [r for _, r in ranked],
    }
    if episodes == 0:
        out["state"] = "stable"
    else:
        share = local / float(episodes)
        out["local_share"] = share
        out["state"] = "local" if share >= 0.6 else "aws" if share <= 0.3 else "mixed"
    return out


# ------------------------------------------------------------------------ serve

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        try:
            if u.path in ("/", "/index.html"):
                with open(DASHBOARD, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif u.path == "/api/data":
                w = parse_qs(u.query).get("window", ["24h"])[0]
                body = json.dumps(analyze(parse_window(w))).encode()
                self._send(200, body, "application/json")
            elif u.path == "/api/export":
                q = parse_qs(u.query)
                self._export(q.get("window", ["7d"])[0], q.get("format", ["json"])[0])
            else:
                self._send(404, b"not found", "text/plain")
        except Exception as e:
            self._send(500, str(e).encode(), "text/plain")


    def _export(self, w, fmt):
        window_s = parse_window(w)
        stamp = time.strftime("%Y%m%d-%H%M")
        if fmt == "csv":
            # Muestras en bruto, enviadas por partes para no cargar todo en memoria.
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition",
                             'attachment; filename="pingmon-%s-%s.csv"' % (w, stamp))
            self.end_headers()
            self.wfile.write(b"fecha,ts,objetivo,rtt_ms\n")
            conn = db_connect()
            cur = conn.execute("SELECT ts, target, rtt_ms FROM samples WHERE ts >= ? ORDER BY ts",
                               (time.time() - window_s,))
            while True:
                rows = cur.fetchmany(5000)
                if not rows:
                    break
                self.wfile.write("".join(
                    "%s,%.3f,%s,%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
                                         ts, tid, "" if rtt is None else "%.2f" % rtt)
                    for ts, tid, rtt in rows).encode())
            conn.close()
        else:
            body = json.dumps(analyze(window_s), indent=1).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition",
                             'attachment; filename="pingmon-%s-%s.json"' % (w, stamp))
            self.end_headers()
            self.wfile.write(body)


def serve():
    cfg = load_config()
    addr = (cfg.get("bind", "127.0.0.1"), int(cfg.get("port", 8787)))
    httpd = ThreadingHTTPServer(addr, Handler)
    log("dashboard en http://%s:%d" % addr)
    httpd.serve_forever()


# ----------------------------------------------------------------------- report

def fmt(v, unit="", nd=1):
    return "—" if v is None else ("%.*f%s" % (nd, v, unit))


def report(window):
    d = analyze(parse_window(window))
    names = {t["id"]: t["name"] for t in d["targets"]}
    print("\nVentana: %s  ·  intervalo %ds\n" % (window, d["interval"]))
    hdr = "%-28s %7s %7s %7s %7s %8s %7s %7s" % (
        "objetivo", "p50", "p95", "p99", "max", "jitter", "pérd.", "score")
    print(hdr)
    print("-" * len(hdr))
    order = sorted((t for t in d["targets"] if t["kind"] != "self"), key=lambda t: (
        {"control": 0, "server": 1, "region": 2}[t["kind"]],
        d["summary"][t["id"]]["score"] or 1e9))
    for t in order:
        s = d["summary"][t["id"]]
        print("%-28s %7s %7s %7s %7s %8s %7s %7s" % (
            t["name"][:28], fmt(s["p50"]), fmt(s["p95"]), fmt(s["p99"]), fmt(s["max"]),
            fmt(s["jitter"]), fmt(None if s["loss"] is None else s["loss"] * 100, "%"),
            fmt(s["score"], nd=0)))
    v = d["verdict"]
    msg = {
        "nodata": "Aún no hay datos suficientes.",
        "stable": "Sin episodios de lag hacia AWS en esta ventana.",
        "local": "El lag coincide con lag en router/ISP: el problema es la red de la oficina.",
        "aws": "El lag aparece solo en el camino a AWS: tiene sentido cambiar de región.",
        "mixed": "Causas mezcladas: parte de los episodios son de la red local, parte del camino a AWS.",
    }[v["state"]]
    print("\nDiagnóstico: %s" % msg)
    if v.get("episodes"):
        print("  %d tramos con lag hacia AWS; %d coinciden con lag local (%d en el propio router)."
              % (v["episodes"], v["local"], v["lan"]))
    if v.get("best_region"):
        print("  Mejor región por score: %s" % names[v["best_region"]])
    if v.get("ignored_controls"):
        print("  Controles que no responden (ignorados): %s" % ", ".join(names[i] for i in v["ignored_controls"]))
    a = d["audit"]
    print("\nAuditoría de red:")
    st = a["sync_stalls"]
    if st["count"]:
        ritmo = ("cada ~%.0f min, con ritmo fijo" if st["regular"] else "cada ~%.0f min de mediana, sin ritmo fijo") % (st["median_gap_s"] / 60) if st["median_gap_s"] else ""
        print("  Parones simultáneos de red: %d (%d verificados con el Mac activo), +%.0f ms de mediana. %s"
              % (st["count"], st["verified"], st["median_added_ms"], ritmo))
    else:
        print("  Sin parones simultáneos de red.")
    if a["mac_pauses"]:
        print("  %d rondas descartadas porque el propio Mac estuvo parado (no es la red)." % a["mac_pauses"])
    for p in a["icmp_vs_tcp"]:
        print("  %s: pérdida por ping %.2f %% vs por TCP %.2f %%%s" % (
            names[p["icmp"]], (p["icmp_loss"] or 0) * 100, (p["tcp_loss"] or 0) * 100,
            "  -> el ping está limitado/bloqueado, no es pérdida real" if (p["icmp_loss"] or 0) > 0.005 and (p["tcp_loss"] or 0) < (p["icmp_loss"] or 0) / 5 else ""))
    e = a["egress"]
    if e["current"]:
        c = e["current"]
        print("  Salida a internet: %s (%s %s), Cloudflare %s. Cambios en la ventana: %d. Comprobaciones fallidas: %d/%d."
              % (c["ip"], c["asn"], c["asname"], c["colo"], max(0, len(e["changes"]) - 1), e["failed"], e["checks"]))
    for tid, p in a["paths"].items():
        print("  Ruta a %s: %d saltos, %d cambios de camino en %d traceroutes." % (
            names.get(tid, tid), len(p["latest"]["hops"]), len(p["changes"]), p["count"]))
    for i in v.get("ignored_servers", []):
        print("  %s no responde desde esta máquina (¿Security Group / whitelist?); se usan las regiones." % names[i])
    if d["unconfigured"]:
        print("  Sin configurar en config.json: %s" % ", ".join(d["unconfigured"]))
    print()


# ---------------------------------------------------------------------- launchd

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/caffeinate</string><string>-is</string>
    <string>{python}</string><string>{script}</string><string>run</string>
  </array>
  <key>WorkingDirectory</key><string>{base}</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"""


def install():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(PLIST_PATH), exist_ok=True)
    with open(PLIST_PATH, "w") as f:
        f.write(PLIST.format(label=LAUNCHD_LABEL, python=sys.executable,
                             script=os.path.abspath(__file__), base=BASE,
                             log=os.path.join(DATA_DIR, "pingmon.log")))
    domain = "gui/%d" % os.getuid()
    subprocess.run(["launchctl", "bootout", domain, PLIST_PATH], capture_output=True)
    subprocess.run(["launchctl", "bootstrap", domain, PLIST_PATH], check=True)
    cfg = load_config()
    port = int(cfg.get("port", 8787))
    host = socket.gethostname()
    if not host.endswith(".local"):
        host += ".local"
    print("Instalado: %s\nLog: %s\nDashboard en este equipo: http://127.0.0.1:%d" % (
        PLIST_PATH, os.path.join(DATA_DIR, "pingmon.log"), port))
    if cfg.get("bind") == "0.0.0.0":
        print("Desde otro equipo de la oficina: http://%s:%d" % (host, port))


def uninstall():
    subprocess.run(["launchctl", "bootout", "gui/%d" % os.getuid(), PLIST_PATH],
                   capture_output=True)
    if os.path.exists(PLIST_PATH):
        os.remove(PLIST_PATH)
    print("Desinstalado (los datos siguen en %s)" % DATA_DIR)


# ------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    sub.add_parser("probe")
    sub.add_parser("serve")
    r = sub.add_parser("report")
    r.add_argument("--window", default="24h")
    sub.add_parser("install")
    sub.add_parser("uninstall")
    a = ap.parse_args()

    if a.cmd == "run":
        threading.Thread(target=_probe_or_die, daemon=True).start()
        serve()
    elif a.cmd == "probe":
        probe_loop()
    elif a.cmd == "serve":
        serve()
    elif a.cmd == "report":
        report(a.window)
    elif a.cmd == "install":
        install()
    elif a.cmd == "uninstall":
        uninstall()


if __name__ == "__main__":
    main()
