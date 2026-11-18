"""Aquisicao de evidencias: copia somente-leitura, SHA-256 no momento da coleta e cadeia de custodia (CSV).
Uso: python forensics/collect_evidence.py --case INC-VA-0712-LAB <arquivo>..."""
import argparse, csv, getpass, hashlib, os, platform, shutil, time
ap = argparse.ArgumentParser(); ap.add_argument("--case", required=True); ap.add_argument("--collector", default=""); ap.add_argument("files", nargs="+"); a = ap.parse_args()
H = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")); ED = f"{H}/evidence/{a.case}"; os.makedirs(ED, exist_ok=True)
coc = f"{ED}/cadeia_de_custodia.csv"; new = not os.path.exists(coc)
start = 1 if new else sum(1 for _ in open(coc))                    # proximo numero (linhas existentes = cabecalho + itens)
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
with open(coc, "a", newline="") as f:
    w = csv.writer(f)
    if new: w.writerow(["id", "arquivo_original", "copia", "sha256_na_coleta", "bytes", "coletado_em_utc", "coletor_declarado", "usuario_so", "host", "metodo", "sha256_reverificado"])
    for i, p in enumerate(a.files, start):
        dst = f"{ED}/EV-{i:02d}_{os.path.basename(p)}"; h = sha(p); shutil.copy2(p, dst); os.chmod(dst, 0o444)
        w.writerow([f"EV-{i:02d}", os.path.abspath(p), dst, h, os.path.getsize(dst), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), a.collector or "[PREENCHER: integrante]", getpass.getuser(), platform.node(), "copia + sha256 (collect_evidence.py)", sha(dst)])
print(open(coc).read())
