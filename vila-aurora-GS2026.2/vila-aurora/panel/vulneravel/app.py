"""PAINEL LEGADO - VERSAO PROPOSITALMENTE VULNERAVEL (reproduz o INC-VA-0712). SOMENTE LABORATORIO.
Falhas: SQL concatenado, erro detalhado ao usuario, conta de DB com acesso total, sem MFA, sem validacao."""
import json, os, sqlite3, time
from flask import Flask, request, render_template_string
app = Flask(__name__); DB = os.environ.get("PANEL_DB", "panel_vuln.db"); LOG = os.environ.get("WEB_LOG", "web_vuln.log")
@app.after_request
def alog(r):
    open(LOG, "a").write(json.dumps({"ts": time.time(), "app": "painel-vuln", "ip": request.remote_addr, "method": request.method, "path": request.full_path, "status": r.status_code}) + "\n"); return r
PAGE = "<h1>Historico de acessos</h1><form><input name=busca value='{{b}}'><button>Buscar</button></form><pre>{{rows}}</pre>"
@app.route("/historico")
def historico():
    b = request.args.get("busca", "")
    try:
        q = "SELECT ts, usuario, porta, resultado FROM access_log WHERE usuario LIKE '%" + b + "%' ORDER BY ts LIMIT 50"   # VULNERAVEL
        rows = sqlite3.connect(DB).execute(q).fetchall()
        return render_template_string(PAGE, b=b, rows="\n".join(" | ".join(map(str, r)) for r in rows))
    except Exception as e:
        return f"ERRO SQL: {e}<br>Consulta: {q}", 500          # VAZA detalhes
if __name__ == "__main__": app.run(os.environ.get("HOST", "127.0.0.1"), 5001)
