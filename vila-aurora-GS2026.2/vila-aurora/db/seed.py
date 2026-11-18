"""Gera banco SINTETICO (nenhum dado pessoal real). Uso: python db/seed.py <arquivo.db> [--pseudo]"""
import hashlib, hmac, os, random, sqlite3, sys, time
from werkzeug.security import generate_password_hash
random.seed(42)
PEPPER = os.environ.get("PSEUDO_KEY", "chave-lab-nao-usar-em-producao").encode()   # em producao: segredo fora do repo
NOMES = ["Ana Souza", "Bruno Lima", "Carla Dias", "Diego Ramos", "Elisa Prado", "Fabio Neri", "Gina Alves", "Hugo Reis", "Iara Pinto", "Joel Matos"]
ESPACOS = ["centro", "escola", "ubs", "horta", "abrigo"]
def pseudo(nome): return "u_" + hmac.new(PEPPER, nome.encode(), hashlib.sha256).hexdigest()[:10]
def main(path, use_pseudo):
    if os.path.exists(path): os.remove(path)
    c = sqlite3.connect(path)
    c.executescript("""CREATE TABLE users(id INTEGER PRIMARY KEY, nome TEXT, email TEXT, cpf_sintetico TEXT, role TEXT, pw_hash TEXT, totp_secret TEXT);
    CREATE TABLE access_log(id INTEGER PRIMARY KEY, ts TEXT, usuario TEXT, porta TEXT, resultado TEXT);
    CREATE TABLE approvals(id INTEGER PRIMARY KEY, ts TEXT, acao TEXT, solicitante TEXT, status TEXT, aprovador TEXT);""")
    roles = ["operador", "tecnico", "coordenacao", "auditor"]
    for i, n in enumerate(NOMES):
        r = roles[i % 4] if i < 8 else "operador"
        c.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?)", (i + 1, n, f"{n.split()[0].lower()}@vilaaurora.example", f"000.000.{i:03d}-00", r,
                  generate_password_hash(f"Senha-Lab-{i}!"), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"))   # TOTP de LAB (fixo) - rotacionar em producao
    for k in range(300):
        n = random.choice(NOMES); u = pseudo(n) if use_pseudo else n
        c.execute("INSERT INTO access_log(ts,usuario,porta,resultado) VALUES(?,?,?,?)",
                  (time.strftime("2026-11-%d %H:%M", time.gmtime(86400 * random.randint(1, 15) + random.randint(0, 86399))), u, f"porta-{random.choice(ESPACOS)}", random.choice(["liberado"] * 9 + ["negado"])))
    c.commit(); print(f"{path}: users={c.execute('select count(*) from users').fetchone()[0]} logs={c.execute('select count(*) from access_log').fetchone()[0]} pseudo={use_pseudo}")
if __name__ == "__main__": main(sys.argv[1], "--pseudo" in sys.argv)
