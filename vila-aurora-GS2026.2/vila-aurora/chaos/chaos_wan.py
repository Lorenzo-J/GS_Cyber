"""Teste de caos RT-23: derruba o link WAN (servico de nuvem) por >= 30 min e mede continuidade local e reconciliacao.
Fases: baseline -> WAN DOWN (30 min) -> WAN UP/reconciliacao. Excursao da camara fria injetada DURANTE a queda."""
import json, os, signal, socket, sqlite3, ssl, subprocess, sys, time, statistics
import psutil
H = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
R = f"{H}/chaos/results"; os.makedirs(R, exist_ok=True); D = f"{H}/edge/data"
BASE, DOWN, TAIL = int(os.environ.get("BASE", 180)), int(os.environ.get("DOWN", 1860)), int(os.environ.get("TAIL", 240))
INTERVAL = 2.0; EXC_AT = BASE + int(DOWN * 0.2); EXC_LEN = int(DOWN * 0.4)
tl = open(f"{R}/timeline.log", "w", buffering=1)
def mark(m): tl.write(f"{time.strftime('%H:%M:%S')} +{int(time.time()-T0):>5}s  {m}\n")
def sh(cmd, **k): return subprocess.Popen(cmd, stdout=open("/dev/null", "w"), stderr=subprocess.STDOUT, start_new_session=True, cwd=H, **k)
def tls_ok(port=8883):
    try:
        c = ssl.create_default_context(cafile=f"{H}/pki/out/ca.crt"); c.load_cert_chain(f"{H}/pki/out/devices/sensor-energia-centro.crt", f"{H}/pki/out/devices/sensor-energia-centro.key")
        with socket.create_connection(("127.0.0.1", port), 2) as s, c.wrap_socket(s, server_hostname="localhost"): return True
    except Exception: return False
def tcp_ok(port=8090):
    try: socket.create_connection(("127.0.0.1", port), 1).close(); return True
    except Exception: return False
def kill_stale():
    for p in psutil.process_iter(["pid", "cmdline"]):
        c = " ".join(p.info["cmdline"] or [])
        if p.info["pid"] != os.getpid() and any(x in c for x in ("edge_agent.py", "cloud_ingest.py", "field_sim.py")):
            try: p.kill()
            except Exception: pass
kill_stale(); time.sleep(1)
for f in ("buffer.db", "cloud.db", "edge.log", "ALARME_ATIVO", "stats.json"):
    try: os.remove(f"{D}/{f}")
    except FileNotFoundError: pass
T0 = time.time(); mark("inicio do teste")
cloud = sh([sys.executable, "edge/cloud_ingest.py"]); edge = sh([sys.executable, "edge/edge_agent.py"]); time.sleep(3)
total = BASE + DOWN + TAIL
sim = subprocess.Popen([sys.executable, "field/field_sim.py", "--duration", str(total), "--interval", str(INTERVAL), "--excursion-at", str(EXC_AT), "--excursion-len", str(EXC_LEN), "--level0", os.environ.get("LEVEL0", "60")],
                       stdout=open(f"{R}/field_sim.out", "w"), stderr=subprocess.STDOUT, start_new_session=True, cwd=H)
mark("baseline: nuvem UP"); samples = []; probes = []; phase = "baseline"; down_t = up_t = None
ep = psutil.Process(edge.pid); mq = next((p for p in psutil.process_iter(["name"]) if p.info["name"] == "mosquitto"), None)
ep.cpu_percent(None); mq and mq.cpu_percent(None); last_net = psutil.net_io_counters(); lo_prev = psutil.net_io_counters(pernic=True).get("lo")
while time.time() - T0 < total + 20:
    el = time.time() - T0
    if phase == "baseline" and el >= BASE: os.killpg(cloud.pid, signal.SIGTERM); cloud.wait(); phase = "wan_down"; down_t = time.time(); mark("WAN DOWN (servico de nuvem derrubado)")
    if phase == "wan_down" and el >= BASE + DOWN:
        cloud = sh([sys.executable, "edge/cloud_ingest.py"]); phase = "wan_up"; up_t = time.time(); mark("WAN UP (reconciliacao inicia)")
    if EXC_AT <= el < EXC_AT + 2.5 : mark("excursao de temperatura da camara fria iniciada (durante WAN DOWN)")
    try: st = json.load(open(f"{D}/stats.json"))
    except Exception: st = {}
    samples.append({"t": round(el, 1), "phase": phase, "edge_cpu": ep.cpu_percent(None), "edge_rss_mb": round(ep.memory_info().rss / 1e6, 1),
                    "mosq_cpu": mq.cpu_percent(None) if mq else 0, "mosq_rss_mb": round(mq.memory_info().rss / 1e6, 1) if mq else 0, "tx_bytes": st.get("tx_bytes", 0), "rx": st.get("rx", 0), "alarms": st.get("alarms", 0)})
    probes.append({"t": round(el, 1), "phase": phase, "local": tls_ok(), "cloud": tcp_ok()})
    time.sleep(5)
mark("fim da coleta")
time.sleep(3); sim.wait()
b = sqlite3.connect(f"{D}/buffer.db"); c = sqlite3.connect(f"{D}/cloud.db")
nbuf = b.execute("select count(*) from buf").fetchone()[0]; nsync = b.execute("select sum(synced) from buf").fetchone()[0]; ncloud = c.execute("select count(*) from readings").fetchone()[0]
recv_min = c.execute("select min(recv) from readings where recv>?", (up_t,)).fetchone()[0]; recv_max = c.execute("select max(recv) from readings").fetchone()[0]
simout = open(f"{R}/field_sim.out").read(); published = int(simout.split("(")[1].split()[0]) if "(" in simout else None
alarms = b.execute("select ts,kind,detail,first_bad_ts from alarms").fetchall()
ev = [json.loads(l) for l in open(f"{D}/edge.log")]
al = [e for e in ev if e["event"] == "ALARME_LOCAL"]; cmds = [e for e in ev if e["event"] == "cmd_bomba"]
during = [a for a in alarms if down_t <= a[0] <= up_t]; dup = sum(e.get("dup") or 0 for e in ev if e["event"] == "sync_ok")
first = next((e for e in ev if e["event"] == "sync_ok" and e["ts"] >= up_t), None); rec_t = round(first["ts"] - up_t, 1) if first else None; rec_n = first["n"] if first else None
pl = lambda ph, k: [p[k] for p in probes if p["phase"] == ph]
res = {"duracao_total_s": total, "baseline_s": BASE, "wan_down_s": round(up_t - down_t), "tail_s": TAIL,
 "leituras_publicadas_pelos_sensores": published, "leituras_no_buffer_da_borda": nbuf, "leituras_sincronizadas_na_borda": int(nsync or 0), "leituras_na_nuvem": ncloud,
 "perda_sensor_para_borda": None if published is None else published - nbuf, "perda_na_reconciliacao(borda-nuvem)": nbuf - ncloud, "duplicatas_descartadas_idempotencia": dup,
 "tempo_reconciliacao_s": rec_t, "backlog_reconciliado_linhas": rec_n, "mttd_alarme_local_s": [round(a[0] - a[3], 2) for a in alarms],
 "alarmes_durante_wan_down": len(during), "comandos_bomba_durante_wan_down": len([e for e in cmds if down_t <= e["ts"] <= up_t]),
 "disponibilidade_local_pct": round(100 * sum(p["local"] for p in probes) / len(probes), 2), "disponibilidade_nuvem_pct": round(100 * sum(p["cloud"] for p in probes) / len(probes), 2),
 "disponibilidade_local_durante_wan_down_pct": round(100 * sum(pl("wan_down", "local")) / max(1, len(pl("wan_down", "local"))), 2),
 "edge_cpu_medio_pct": round(statistics.mean(s["edge_cpu"] for s in samples), 2), "edge_cpu_max_pct": max(s["edge_cpu"] for s in samples), "edge_rss_max_mb": max(s["edge_rss_mb"] for s in samples),
 "broker_cpu_medio_pct": round(statistics.mean(s["mosq_cpu"] for s in samples), 2), "broker_rss_max_mb": max(s["mosq_rss_mb"] for s in samples),
 "banda_borda_para_nuvem_bytes": samples[-1]["tx_bytes"], "buffer_db_bytes": os.path.getsize(f"{D}/buffer.db")}
json.dump(res, open(f"{R}/metrics.json", "w"), indent=2); json.dump({"samples": samples, "probes": probes}, open(f"{R}/samples.json", "w"))
kill_stale(); mark("metricas gravadas"); print(json.dumps(res, indent=2))
