"""PAINEL CORRIGIDO. Controles: consulta parametrizada, validacao de entrada, erros genericos, camada WAF,
MFA (TOTP) + RBAC (operador/tecnico/coordenacao/auditor), pseudonimizacao, acessibilidade (WCAG 2.1 AA)."""
import json, os, re, secrets, sqlite3, time, uuid
import pyotp
from flask import Flask, request, session, redirect, url_for, render_template_string, abort
from werkzeug.security import check_password_hash
app = Flask(__name__); app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
DB = os.environ.get("PANEL_DB", "panel_ok.db"); LOG = os.environ.get("WEB_LOG", "web_ok.log")
SAFE_Q = re.compile(r"^[\w .@-]{0,40}$")                       # lista de PERMISSAO (allow-list)
WAF = re.compile(r"(?i)(union\s+select|or\s+1\s*=\s*1|--|/\*|;\s*drop|sleep\(|information_schema|sqlite_master|'\s*or\s*')")
PERMS = {"operador": {"ver_painel"}, "tecnico": {"ver_painel", "ver_historico"}, "coordenacao": {"ver_painel", "ver_historico", "aprovar"}, "auditor": {"ver_historico", "ver_auditoria"}}
FAILS = {}                                                      # limitador simples de tentativas de login
def jlog(ev, **k): open(LOG, "a").write(json.dumps({"ts": time.time(), "app": "painel-ok", "ip": request.remote_addr, "event": ev, "user": session.get("u"), **k}) + "\n")
def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
@app.before_request
def waf():                                                      # defesa em profundidade (nao substitui a parametrizacao)
    for k, v in list(request.args.items()) + list(request.form.items()):
        if WAF.search(v): jlog("waf_block", param=k, payload=v[:80]); abort(403)
def need(perm):
    def deco(f):
        def w(*a, **k):
            if "u" not in session: return redirect(url_for("login"))
            if perm != "*" and perm not in PERMS.get(session["role"], set()): jlog("acesso_negado", perm=perm); abort(403)
            return f(*a, **k)
        w.__name__ = f.__name__; return w
    return deco
BASE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{t}} - Rede Vila Aurora</title><style>body{font:18px/1.6 system-ui;margin:0;color:#111;background:#fff}header,main{max-width:46rem;margin:auto;padding:1rem}
header{border-bottom:3px solid #0b5}a,button,input{font:inherit}a{color:#0043a8}button{background:#0b4;color:#000;border:2px solid #063;padding:.6rem 1rem;border-radius:6px;cursor:pointer}
input{border:2px solid #333;padding:.5rem;width:100%;max-width:20rem}:focus{outline:4px solid #f90;outline-offset:2px}td,th{border:1px solid #666;padding:.4rem;text-align:left}
.skip{position:absolute;left:-999px}.skip:focus{left:1rem;top:1rem;background:#fff;padding:.5rem}.erro{color:#8a0000;font-weight:bold}</style></head><body>
<a class="skip" href="#conteudo">Pular para o conteudo</a><header><strong>Rede Vila Aurora</strong>
{% if s %}<nav aria-label="Menu principal"> <a href="/">Inicio</a> | <a href="/historico">Historico de acessos</a> | <a href="/aprovacoes">Aprovacoes</a> | <a href="/sair">Sair</a></nav>{% endif %}</header>
<main id="conteudo" tabindex="-1">{{body|safe}}</main></body></html>"""
def page(t, body): return render_template_string(BASE, t=t, body=body, s="u" in session)
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u, p, code = request.form.get("usuario", ""), request.form.get("senha", ""), request.form.get("codigo", "")
        if FAILS.get(request.remote_addr, 0) >= 5: jlog("login_bloqueado"); abort(429)
        row = db().execute("SELECT * FROM users WHERE email=?", (u,)).fetchone()
        if row and check_password_hash(row["pw_hash"], p) and pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1):
            session.update(u=row["email"], role=row["role"]); FAILS.pop(request.remote_addr, None); jlog("login_ok", role=row["role"]); return redirect("/")
        FAILS[request.remote_addr] = FAILS.get(request.remote_addr, 0) + 1; jlog("login_falha"); msg = '<p class="erro" role="alert">Usuario, senha ou codigo incorretos.</p>'
    return page("Entrar", f"""<h1>Entrar</h1>{msg}<form method=post><p><label for=usuario>E-mail</label><br><input id=usuario name=usuario type=email autocomplete=username required></p>
<p><label for=senha>Senha</label><br><input id=senha name=senha type=password autocomplete=current-password required></p>
<p><label for=codigo>Codigo de 6 digitos do aplicativo autenticador</label><br><input id=codigo name=codigo inputmode=numeric pattern="[0-9]{{6}}" autocomplete=one-time-code required></p><button>Entrar</button></form>""")
@app.route("/")
@need("*")
def home(): return page("Inicio", f"<h1>Ola!</h1><p>Voce entrou como <strong>{session['role']}</strong>.</p>")
@app.route("/historico")
@need("ver_historico")
def historico():
    b = request.args.get("busca", "")
    if not SAFE_Q.match(b): jlog("entrada_invalida", campo="busca"); return page("Historico", '<h1>Historico de acessos</h1><p class="erro" role="alert">Use apenas letras, numeros, espaco, ponto, arroba e hifen (ate 40 caracteres).</p>'), 400
    rows = db().execute("SELECT ts, usuario, porta, resultado FROM access_log WHERE usuario LIKE ? ORDER BY ts LIMIT 50", (f"%{b}%",)).fetchall()   # PARAMETRIZADA
    tr = "".join(f"<tr><td>{r['ts']}</td><td>{r['usuario']}</td><td>{r['porta']}</td><td>{r['resultado']}</td></tr>" for r in rows)
    return page("Historico", f'<h1>Historico de acessos</h1><form><label for=b>Buscar por codigo de usuario</label><br><input id=b name=busca value="{b}"> <button>Buscar</button></form><table><caption>Ultimos acessos (usuarios pseudonimizados)</caption><tr><th scope=col>Data</th><th scope=col>Usuario</th><th scope=col>Porta</th><th scope=col>Resultado</th></tr>{tr}</table>')
@app.route("/aprovacoes")
@need("aprovar")
def aprov(): return page("Aprovacoes", "<h1>Acoes aguardando aprovacao humana</h1><p>Somente a coordenacao pode aprovar acoes de alto impacto (ex.: desligar a bomba do abrigo).</p>")
@app.route("/sair")
def sair(): session.clear(); return redirect("/login")
@app.errorhandler(Exception)
def generico(e):
    code = getattr(e, "code", 500); rid = uuid.uuid4().hex[:8]; jlog("erro", code=code, rid=rid, tipo=type(e).__name__)
    return page("Erro", f'<h1>Algo deu errado</h1><p>Nao foi possivel concluir. Informe o codigo <strong>{rid}</strong> ao tecnico.</p>'), code   # sem detalhes internos
if __name__ == "__main__": app.run(os.environ.get("HOST", "127.0.0.1"), 5002)
