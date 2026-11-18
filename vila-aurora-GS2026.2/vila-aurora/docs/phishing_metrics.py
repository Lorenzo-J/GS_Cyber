"""Calcula metricas de phishing a partir da exportacao 'Raw Events' do Gophish (CSV). Uso: phishing_metrics.py <cenario> <arquivo.csv>
Colunas esperadas (nomes podem variar em maiusculas): email, time, message[, details]. 'details' e IGNORADA de proposito (pode conter dados digitados)."""
import csv, json, os, statistics, sys, datetime as dt
name, path = sys.argv[1], sys.argv[2]
KEY = {"sent": ("email sent",), "open": ("email opened",), "click": ("clicked link",), "submit": ("submitted data",), "report": ("email reported",)}
def ts(s):
    s = s.strip().replace("Z", "+00:00")
    for f in (None,):
        try: return dt.datetime.fromisoformat(s[:32])
        except Exception: pass
    for f in ("%Y-%m-%d %H:%M:%S.%f %z %Z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S"):
        try: return dt.datetime.strptime(s[:len(dt.datetime.now().strftime(f)) + 12], f)
        except Exception: pass
    raise ValueError(f"nao entendi o horario: {s!r}")
rows = list(csv.DictReader(open(path, newline="", encoding="utf-8-sig"))); low = lambda r: {k.strip().lower(): v for k, v in r.items()}
ev = {k: {} for k in KEY}
for r in map(low, rows):
    m = (r.get("message") or "").strip().lower(); em = (r.get("email") or "").strip().lower()
    if not em: continue
    for k, names in KEY.items():
        if m in names and em not in ev[k]: ev[k][em] = ts(r["time"])
n = len(ev["sent"]); assert n > 0, "nenhum 'Email Sent' encontrado: confira o CSV (Raw Events)"
rep_t = [(ev["report"][e] - ev["sent"][e]).total_seconds() for e in ev["report"] if e in ev["sent"]]
res = {"cenario": name, "enviados": n, "abertos": len(ev["open"]), "cliques": len(ev["click"]), "submissoes": len(ev["submit"]), "reportes": len(ev["report"]),
       "taxa_abertura_pct": round(100 * len(ev["open"]) / n, 1), "taxa_clique_pct": round(100 * len(ev["click"]) / n, 1), "taxa_submissao_pct": round(100 * len(ev["submit"]) / n, 1), "taxa_reporte_pct": round(100 * len(ev["report"]) / n, 1),
       "tempo_mediano_ate_reporte_s": round(statistics.median(rep_t), 1) if rep_t else None, "fonte": os.path.basename(path), "nota": "Alvos = contas ficticias da equipe; metricas refletem o comportamento da equipe."}
os.makedirs("tests/results", exist_ok=True); json.dump(res, open(f"tests/results/phishing_metrics_{name}.json", "w"), indent=1, ensure_ascii=False); print(json.dumps(res, indent=1, ensure_ascii=False))
