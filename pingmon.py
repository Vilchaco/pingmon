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
    cfg["active_targets"] = targets
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
    try:
        ip = resolve(t["host"])
    except Exception as e:  # DNS caído cuenta como pérdida
        return None, None, str(e)
    if t.get("method") == "icmp":
        rtt = probe_icmp(ip, timeout)
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

    pool = ThreadPoolExecutor(max_workers=max(1, len(targets)))
    next_tick = time.time()
    last_prune = 0
    while not (stop and stop.is_set()):
        ts = time.time()
        results = list(pool.map(lambda t: probe_target(t, timeout), targets))
        rows = []
        for t, (rtt, ip, err) in zip(targets, results):
            rows.append((ts, t["id"], rtt, ip))
            if err:
                log("%s: %s" % (t["id"], err))
        try:
            conn.executemany("INSERT INTO samples VALUES (?,?,?,?)", rows)
            conn.commit()
            if ts - last_prune > 3600:
                conn.execute("DELETE FROM samples WHERE ts < ?", (ts - retention,))
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

    stalled = stalled_rounds(targets, by_target)
    if stalled:
        for tid in by_target:
            by_target[tid] = [r for r in by_target[tid] if r[0] not in stalled]

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
        "stalled_rounds": len(stalled),
    }


def stalled_rounds(targets, by_target):
    """Rondas en las que el propio equipo se congeló, no la red.

    Si varios destinos TCP con latencias normales distintas (p. ej. 40 y 65 ms)
    devuelven a la vez casi el mismo RTT (±2 ms) y todos por encima de lo normal,
    el retraso es del Mac (suspensión, CPU), no de ningún camino de red.
    """
    tcp = [t["id"] for t in targets if t.get("method", "tcp") == "tcp"]
    base = {}
    for tid in tcp:
        ok = sorted(r for _, r in by_target[tid] if r is not None)
        base[tid] = pct(ok, 50)
    rounds = {}
    for tid in tcp:
        for ts, rtt in by_target[tid]:
            if rtt is not None and base[tid]:
                rounds.setdefault(ts, []).append((rtt, base[tid]))
    out = set()
    for ts, vals in rounds.items():
        if len(vals) < 3:
            continue
        rtts = [v for v, _ in vals]
        bases = [b for _, b in vals]
        if (max(rtts) - min(rtts) <= 2.0 and max(bases) - min(bases) >= 10
                and all(v > b + 15 for v, b in vals)):
            out.add(ts)
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
    gw = [i for i in controls if i == "gateway"]
    inet = [i for i in controls if i != "gateway"]
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
    order = sorted(d["targets"], key=lambda t: (
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
        if "gateway" in v["ignored_controls"]:
            print("    -> Router: revisa Ajustes del Sistema > Privacidad y seguridad > Red local (activa python3/Terminal).")
    if d.get("stalled_rounds"):
        print("  %d rondas descartadas porque el propio equipo se congeló (no es la red)." % d["stalled_rounds"])
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
