"""Motor de deteccao (RT-13). Le logs centralizados (JSON lines e log do Mosquitto) e emite alertas com tecnica MITRE ATT&CK.
Espelha as regras Wazuh em siem/wazuh_local_rules.xml. Uso: python siem/detect.py --out alerts.jsonl <fonte:arquivo> ..."""
import argparse, json, re, sys, time, urllib.parse
ALLOW_VPN_IPS = {"198.51.100.10", "198.51.100.11"}          # IPs de gerencia conhecidos (faixa de documentacao RFC 5737)
BUSINESS_HOURS = range(6, 23); TZ = -3                        # Sao Paulo (UTC-3)
SQLI = re.compile(r"(?i)(union(\s|\+|%20)+select|\bor\b\s*1\s*=\s*1|sqlite_master|information_schema|'\s*(or|and)\s|--|/\*|;\s*drop|sleep\()")
TLS_BAD = re.compile(r"certificate verify failed|peer did not return a certificate|tlsv1 alert|unknown ca")
ALLOWED_ACTORS = {"edge-rule", "coordenacao-aprovado"}
def lhour(ts): return (time.gmtime(ts + TZ * 3600)).tm_hour
def rules(src, rec):
    out = []; ts = rec.get("ts", 0)
    if rec.get("event") == "vpn_login":                                                       # (a) login VPN anomalo
        why = []
        if rec.get("src_ip") not in ALLOW_VPN_IPS: why.append("IP de origem fora da lista conhecida")
        if lhour(ts) not in BUSINESS_HOURS: why.append(f"fora do horario ({lhour(ts):02d}h local)")
        if rec.get("mfa") is False: why.append("sem MFA")
        if why: out.append(("R-VPN-01", "high", "T1078 Valid Accounts / T1133 External Remote Services", "; ".join(why)))
    p = urllib.parse.unquote_plus(rec.get("path", "")) + " " + str(rec.get("payload", ""))
    q = urllib.parse.unquote_plus(rec.get("path", "")).split("?", 1)[-1] if "?" in rec.get("path", "") else ""
    if src.startswith("web") and "'" in q and not SQLI.search(p):                                  # sonda de SQLi (aspas isoladas)
        out.append(("R-SQLI-02", "medium", "T1190 Exploit Public-Facing Application", f"sonda de SQLi (aspas) em: {q[:60]}"))
    if (src.startswith("web") and rec.get("path") and SQLI.search(p)) or rec.get("event") == "waf_block":   # (b) padrao SQLi
        out.append(("R-SQLI-01", "critical" if rec.get("status") == 200 else "high", "T1190 Exploit Public-Facing Application", f"padrao de SQLi em: {p.strip()[:90]}"))
    if src == "mqtt" and TLS_BAD.search(rec.get("raw", "")):                                    # (c) dispositivo sem certificado valido
        out.append(("R-DEV-01", "high", "T1078 / T1557 Adversary-in-the-Middle", "conexao MQTT rejeitada por certificado invalido/ausente/revogado"))
    if src == "mqtt" and rec.get("raw", "").find("Denied PUBLISH") >= 0:
        out.append(("R-DEV-02", "medium", "T1565 Data Manipulation", "dispositivo tentou publicar fora da propria ACL"))
    ev = rec.get("event")                                                                          # (d) atuador fora de horario/perfil
    if ev in ("actuator_cmd", "pump_schedule_change"):
        actor = rec.get("actor", "?"); why = []
        if actor not in ALLOWED_ACTORS: why.append(f"ator fora do perfil esperado ({actor})")
        if lhour(ts) < 6 and actor != "edge-rule": why.append(f"fora do horario ({lhour(ts):02d}h local)")
        if why: out.append(("R-ACT-01", "critical", "T0831 Manipulation of Control / T1565", "; ".join(why)))
    return out
def parse(src, line):
    line = line.strip()
    if not line: return None
    if src == "mqtt":
        m = re.match(r"^(\d+): (.*)$", line); return {"ts": int(m.group(1)), "raw": m.group(2)} if m else None
    try: return json.loads(line)
    except Exception: return None
def follow(out, sources, secs):
    import os
    pos = {s: (os.path.getsize(s.split(":", 1)[1]) if os.path.exists(s.split(":", 1)[1]) else 0) for s in sources}; end = time.time() + secs   # tempo real: comeca no FIM do arquivo
    with open(out, "a") as fo:
        while time.time() < end:
            for s in sources:
                src, path = s.split(":", 1)
                try:
                    with open(path, errors="replace") as f:
                        f.seek(pos[s]); chunk = f.read(); pos[s] = f.tell()
                except FileNotFoundError: continue
                for line in chunk.splitlines():
                    rec = parse(src, line)
                    for rid, sev, mitre, why in (rules(src, rec) if rec else []):
                        fo.write(json.dumps({"ts": rec.get("ts"), "rule": rid, "severity": sev, "mitre": mitre, "why": why, "detected_at": time.time(), "source": src}) + "\n"); fo.flush()
            time.sleep(0.25)
def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--follow", type=int, default=0, help="segundos acompanhando os logs (tempo real)"); ap.add_argument("--out", default="siem/alerts.jsonl"); ap.add_argument("sources", nargs="+"); a = ap.parse_args()
    if a.follow: return follow(a.out, a.sources, a.follow)
    n = 0; seen = set()
    with open(a.out, "w") as fo:
        for s in a.sources:
            src, path = s.split(":", 1)
            for line in open(path, errors="replace"):
                rec = parse(src, line)
                if not rec: continue
                for rid, sev, mitre, why in rules(src, rec):
                    key = (rid, rec.get("ts"), why, rec.get("raw") or rec.get("path"))
                    if key in seen: continue
                    seen.add(key); n += 1
                    fo.write(json.dumps({"ts": rec.get("ts"), "rule": rid, "severity": sev, "mitre": mitre, "why": why, "detected_at": time.time(), "source": src, "ip": rec.get("ip") or rec.get("src_ip"), "device": rec.get("device")}) + "\n")
    print(f"{n} alertas -> {a.out}")
if __name__ == "__main__": main()
