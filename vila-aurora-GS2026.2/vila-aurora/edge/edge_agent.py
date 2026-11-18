"""No de borda (UBS). Opera de forma autonoma: recebe MQTT local, aplica regras locais, grava em buffer
SQLite (store-and-forward) e sincroniza com a nuvem quando o link existe, com reconciliacao idempotente."""
import argparse, json, os, sqlite3, ssl, threading, time, urllib.request, urllib.error
import paho.mqtt.client as mqtt

H = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
PKI = os.environ.get("PKI", f"{H}/pki/out"); DATA = f"{H}/edge/data"; os.makedirs(DATA, exist_ok=True)
EDGE_ID = "edge-ubs"
COLD_MIN, COLD_MAX, COLD_N = 2.0, 8.0, 3          # faixa segura da camara fria; N leituras consecutivas
PUMP_LOW, PUMP_HIGH = 25.0, 90.0                   # limites locais da bomba (% do reservatorio)
lock = threading.Lock()
db = sqlite3.connect(f"{DATA}/buffer.db", check_same_thread=False)
db.executescript("""CREATE TABLE IF NOT EXISTS buf(seq INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT, ts REAL,
 payload TEXT, synced INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS alarms(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, detail TEXT, first_bad_ts REAL);""")
STATS = {"rx": 0, "tx_bytes": 0, "tx_batches": 0, "sync_fail": 0, "alarms": 0}
cold_bad = []; logf = open(f"{DATA}/edge.log", "a", buffering=1)

def log(ev, **k):
    logf.write(json.dumps({"ts": time.time(), "host": EDGE_ID, "event": ev, **k}) + "\n")

def on_msg(cl, ud, m):
    dev = m.topic.rsplit("/", 1)[-1]
    try: p = json.loads(m.payload)
    except Exception: log("payload_invalido", device=dev); return
    now = time.time()
    with lock:
        db.execute("INSERT INTO buf(device,ts,payload) VALUES(?,?,?)", (dev, p.get("ts", now), m.payload.decode())); db.commit()
    STATS["rx"] += 1
    if "temp_c" in p:                      # regra local 1: alarme da camara fria (NAO depende da nuvem)
        bad = not (COLD_MIN <= p["temp_c"] <= COLD_MAX)
        cold_bad.append((p["ts"], bad)); del cold_bad[:-COLD_N]
        if len(cold_bad) == COLD_N and all(b for _, b in cold_bad):
            first = cold_bad[0][0]
            with lock:
                dup = db.execute("SELECT 1 FROM alarms WHERE kind='COLD_CHAIN' AND ts>?", (now - 60,)).fetchone()
                if not dup:
                    db.execute("INSERT INTO alarms(ts,kind,detail,first_bad_ts) VALUES(?,?,?,?)",
                               (now, "COLD_CHAIN", f"temp={p['temp_c']}C fora de {COLD_MIN}-{COLD_MAX}C", first)); db.commit()
                    STATS["alarms"] += 1; log("ALARME_LOCAL", kind="COLD_CHAIN", temp=p["temp_c"], mttd_s=round(now - first, 3))
                    cl.publish("vila/status/edge-agent", json.dumps({"alarm": "COLD_CHAIN", "ts": now}))
                    open(f"{DATA}/ALARME_ATIVO", "w").write(f"COLD_CHAIN {now}")   # sirene/LED local
    if "level_pct" in p:                   # regra local 2: limites da bomba (dentro do envelope seguro)
        if p["level_pct"] < PUMP_LOW: cl.publish("vila/cmd/bomba-escola", json.dumps({"action": "start", "src": "edge-rule"})); log("cmd_bomba", action="start")
        elif p["level_pct"] >= PUMP_HIGH: cl.publish("vila/cmd/bomba-escola", json.dumps({"action": "stop", "src": "edge-rule"})); log("cmd_bomba", action="stop")

def sync_loop(url, stop):
    backoff = 1
    while not stop.is_set():
        with lock: rows = db.execute("SELECT seq,device,ts,payload FROM buf WHERE synced=0 ORDER BY seq LIMIT 500").fetchall()
        if rows:
            body = json.dumps({"edge": EDGE_ID, "rows": rows}).encode()
            try:
                r = urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type": "application/json", "X-Edge-Id": EDGE_ID}), timeout=3)
                ok = json.loads(r.read())
                with lock: db.execute("UPDATE buf SET synced=1 WHERE seq BETWEEN ? AND ?", (rows[0][0], rows[-1][0])); db.commit()
                STATS["tx_bytes"] += len(body); STATS["tx_batches"] += 1; backoff = 1
                log("sync_ok", n=len(rows), inserted=ok.get("inserted"), dup=ok.get("duplicates"))
                continue
            except Exception as e:
                STATS["sync_fail"] += 1; log("sync_falha", err=type(e).__name__, pendentes=len(rows)); backoff = min(backoff * 2, 5)
        stop.wait(backoff if rows else 1)

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, default=8883)
    ap.add_argument("--cloud", default="http://127.0.0.1:8090/ingest")   # em producao: dentro do tunel WireGuard
    a = ap.parse_args()
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="edge-agent")
    c.tls_set(ca_certs=f"{PKI}/ca.crt", certfile=f"{PKI}/devices/edge-agent.crt", keyfile=f"{PKI}/devices/edge-agent.key", tls_version=ssl.PROTOCOL_TLSv1_2)
    c.on_message = on_msg; c.connect(a.host, a.port, 30); c.subscribe("vila/telemetria/#"); c.loop_start()
    stop = threading.Event(); threading.Thread(target=sync_loop, args=(a.cloud, stop), daemon=True).start()
    log("edge_start")
    try:
        while True: time.sleep(5); json.dump(STATS, open(f"{DATA}/stats.json", "w"))
    except KeyboardInterrupt: stop.set()
if __name__ == "__main__": main()
