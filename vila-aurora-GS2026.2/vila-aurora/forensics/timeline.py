"""Linha do tempo consolidada (UTC) + mapeamento MITRE ATT&CK. Marca quais eventos sao reais (capturados) e quais sinteticos."""
import csv, json, re, sys, time, urllib.parse
H = sys.path[0] + "/.."; L = f"{H}/forensics/lab_logs"; rows = []
iso = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}"
MAP = {"email_sent": ("TA0001 Initial Access", "T1566.002 Spearphishing Link"), "link_clicked": ("TA0002 Execution", "T1204.001 User Execution: Malicious Link"),
       "credentials_submitted": ("TA0006 Credential Access", "T1598.003 / T1056.003 Web Portal Capture"), "vpn_login": ("TA0001 Initial Access / TA0003 Persistence", "T1078 Valid Accounts; T1133 External Remote Services"),
       "pump_schedule_change": ("ICS Impair Process Control", "T0836 Modify Parameter (ICS)")}
def add(t, src, real, ev, det, tac, tec): rows.append([iso(t), src, "REAL" if real else "SINTETICO", ev, det, tac, tec])
for f in ("gophish", "vpn", "painel_audit"):
    for l in open(f"{L}/{f}.jsonl"):
        d = json.loads(l); tac, tec = MAP[d["event"]]; add(d["ts"], f, not d.get("synthetic"), d["event"], (d.get("note") or d.get("to") or d.get("user") or "") + (f" ip={d['ip']}" if d.get("ip") else d.get("src_ip", "") and f" ip={d['src_ip']}"), tac, tec)
for l in open(f"{L}/web_painel_vuln.jsonl"):
    d = json.loads(l); q = urllib.parse.unquote_plus(d["path"]); u = "UNION" in q.upper()
    add(d["ts"], "web", True, "http_request", f"{q[:80]} -> HTTP {d['status']}", "TA0001 Initial Access / TA0009 Collection", "T1190 Exploit Public-Facing Application" + ("; T1213 Data from Information Repositories" if u else ""))
for l in open(f"{L}/mosquitto_trecho.log"):
    m = re.match(r"^(\d+): (.*)$", l.strip())
    if m and ("verify failed" in m.group(2) or "did not return" in m.group(2)): add(int(m.group(1)), "broker-mqtt", True, "tls_rejeitado", m.group(2)[:90] + " (comando ao atuador BLOQUEADO)", "ICS Impair Process Control (tentativa)", "T0855 Unauthorized Command Message")
for l in open(f"{H}/siem/alerts.jsonl"):
    d = json.loads(l); add(d["ts"], "siem", True, "ALERTA " + d["rule"], d["why"][:90], "Deteccao", d["mitre"])
rows.sort(key=lambda r: r[0]); t0 = rows[0][0]
with open(f"{H}/forensics/timeline.csv", "w", newline="") as f: w = csv.writer(f); w.writerow(["ts_utc", "fonte", "origem", "evento", "detalhe", "tatica", "tecnica"]); w.writerows(rows)
print(f"{len(rows)} eventos | inicio {t0} UTC"); [print(" | ".join(r[:4])) for r in rows[:40]]
