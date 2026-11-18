"""Uso defensivo de IA (RT-16): Isolation Forest sobre telemetria SINTETICA. Treino so com dados normais; teste com anomalias rotuladas.
Mede precisao, revocacao, F1 e taxa de falsos positivos. Uso: python ai/anomaly.py"""
import json, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
def feats(x, w=6):
    s = np.convolve(x, np.ones(w) / w, "same"); d = np.r_[0, np.diff(x)]; v = np.array([x[max(0, i - w):i + 1].std() for i in range(len(x))])
    return np.c_[x, x - s, d, v]
def gen(n, rng, anom):
    t = np.arange(n); y = np.zeros(n, int)
    cam = 4.5 + 0.3 * np.sin(t / 40) + rng.normal(0, 0.25, n)             # camara fria
    for s in rng.choice(n - 30, anom, replace=False):                       # falha de compressor: sobe gradualmente
        L = rng.integers(8, 25); cam[s:s + L] += np.linspace(0, rng.uniform(5, 9), L); y[s:s + L] = 1
    for s in rng.choice(n - 5, anom, replace=False):                        # sensor travado/spike
        cam[s] = rng.choice([-3, 20]); y[s] = 1
    return cam, y
rng = np.random.default_rng(2026)
tr, _ = gen(6000, rng, 0); va, yva = gen(3000, rng, 14); te, yte = gen(3000, rng, 14)      # treino / validacao / teste (separados)
m = IsolationForest(n_estimators=200, contamination="auto", random_state=0).fit(feats(tr))
sc_va, sc_te = -m.score_samples(feats(va)), -m.score_samples(feats(te))                       # maior = mais anomalo
def ev(y, pred):
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {"precisao": round(precision_score(y, pred, zero_division=0), 3), "revocacao": round(recall_score(y, pred), 3), "f1": round(f1_score(y, pred), 3),
            "falsos_positivos": int(fp), "taxa_falso_positivo": round(fp / (fp + tn), 4), "falsos_negativos": int(fn), "alertas": int(pred.sum())}
base = ev(yte, (m.predict(feats(te)) == -1).astype(int))                                      # limiar padrao do sklearn
best = max(np.quantile(sc_va, np.linspace(0.80, 0.995, 80)), key=lambda th: f1_score(yva, (sc_va > th).astype(int)))   # limiar escolhido SO na validacao
tuned = ev(yte, (sc_te > best).astype(int))
res = {"amostras_treino(normais)": 6000, "amostras_teste": 3000, "anomalias_reais_no_teste": int(yte.sum()), "limiar_padrao": base, "limiar_ajustado_na_validacao": tuned, "limiar_valor": round(float(best), 4),
       "aviso": "Dados sinteticos: metricas provavelmente otimistas; validar com telemetria real antes de producao."}
json.dump(res, open("ai/metrics.json", "w"), indent=2, ensure_ascii=False); print(json.dumps(res, indent=2, ensure_ascii=False))
