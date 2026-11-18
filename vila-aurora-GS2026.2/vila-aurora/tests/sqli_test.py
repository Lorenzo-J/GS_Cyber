"""Teste de SQL Injection ANTES (painel vulneravel) e DEPOIS (painel corrigido). Alvo: apenas 127.0.0.1 (lab proprio)."""
import http.cookiejar, json, sqlite3, sys, urllib.error, urllib.parse, urllib.request, pyotp
V, C = "http://127.0.0.1:5001", "http://127.0.0.1:5002"
PAYLOADS = {"P1 erro de sintaxe": "'", "P2 tautologia": "x' OR 1=1 --", "P3 UNION (extrai tabela users)": "zzz' UNION SELECT email, nome, cpf_sintetico, role FROM users --",
            "P4 enumeracao de schema": "zzz' UNION SELECT name, sql, '', '' FROM sqlite_master --"}
def nrows(b): return max(b.count("\n") - 1, b.count("<tr><td>"))
def leaked(b): return any(x in b for x in ("@vilaaurora.example", "000.000.", "CREATE TABLE")) or nrows(b) >= 40
def get(op, path, q):
    try:
        r = op.open(f"{path}?busca={urllib.parse.quote(q)}", timeout=5); return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
out = []; P = lambda *a: (print(*a), out.append(" ".join(map(str, a))))
P("=== ANTES: painel vulneravel (sem login, DB com acesso total) ===")
op = urllib.request.build_opener(); vuln_leak = 0
for n, p in PAYLOADS.items():
    st, body = get(op, V + "/historico", p); leak = leaked(body); vuln_leak += leak
    P(f"{n:34} payload={p!r}\n   -> HTTP {st} | linhas~{nrows(body)} | vazou dados/todos os registros: {leak} | erro detalhado exposto: {'ERRO SQL' in body}")
P("\n=== DEPOIS: painel corrigido (login com senha + TOTP) ===")
cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
code = pyotp.TOTP("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").now()
op.open(C + "/login", urllib.parse.urlencode({"usuario": "bruno@vilaaurora.example", "senha": "Senha-Lab-1!", "codigo": code}).encode())
st, body = get(op, C + "/historico", "u_"); P(f"busca legitima 'u_' -> HTTP {st} | linhas de tabela: {body.count('<tr><td>')}")
blocked = 0
for n, p in PAYLOADS.items():
    st, body = get(op, C + "/historico", p); leak = leaked(body); blocked += (st in (400, 403)) and not leak
    P(f"{n:34} -> HTTP {st} | vazou: {leak} | trace/SQL exposto: {'Traceback' in body or 'SELECT' in body}")
P("\n=== Causa raiz isolada (sem WAF e sem validacao): mesma consulta parametrizada, mesmos payloads ===")
c = sqlite3.connect("/tmp/panel_ok.db"); root_ok = 0
for n, p in PAYLOADS.items():
    rows = c.execute("SELECT ts, usuario, porta, resultado FROM access_log WHERE usuario LIKE ? ORDER BY ts LIMIT 50", (f"%{p}%",)).fetchall()
    leak = any("@vilaaurora" in str(r) or "CREATE TABLE" in str(r) for r in rows); root_ok += (not leak); P(f"{n:34} -> {len(rows)} linhas, vazou: {leak}")
P(f"\nRESUMO: vulneravel vazou em {vuln_leak}/4 payloads | corrigido bloqueou {blocked}/4 na borda da aplicacao | causa raiz neutraliza {root_ok}/4")
open("tests/results/sqli_evidence.txt", "w").write("\n".join(out)); sys.exit(0 if (vuln_leak >= 3 and blocked == 4 and root_ok == 4) else 1)
