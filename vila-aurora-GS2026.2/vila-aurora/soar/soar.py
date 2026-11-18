"""SOAR minimo (RT-15). Acoes de BAIXO risco executam automaticamente; ALTO impacto exige aprovacao humana (RBAC: coordenacao).
Modo padrao: dry-run para acoes de rede/VPN (no lab sem kernel WireGuard). Uso: soar.py run alerts.jsonl | approve <id> --by <email> | list"""
import argparse, json, os, subprocess, sys, time
H = os.path.abspath(os.path.join(os.path.dirname(__file__), "..")); ST = f"{H}/soar/state"; os.makedirs(ST, exist_ok=True)
AUDIT = f"{ST}/audit.jsonl"; PEND = f"{ST}/pending.json"; BLOCK = f"{ST}/blocklist_ips.txt"
def audit(**k): open(AUDIT, "a").write(json.dumps({"ts": time.time(), **k}) + "\n")
def revoke_cert(dev):   # LOW
    r = subprocess.run(["bash", f"{H}/pki/revoke.sh", dev], capture_output=True, text=True); audit(action="revoke_cert", device=dev, ok=r.returncode == 0, auto=True); return r.returncode == 0
import ipaddress
NEVER_NETS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]   # explicito (is_private inclui faixas de documentacao)
SAFE_NEVER_BLOCK = {"198.51.100.10", "198.51.100.11"}               # gerencia conhecida
def block_ip(ip):       # LOW (lista + regra nftables gerada)
    a = ipaddress.ip_address(ip)
    if any(a in ipaddress.ip_network(n) for n in NEVER_NETS) or ip in SAFE_NEVER_BLOCK: audit(action="block_ip_recusado", ip=ip, motivo="loopback/privado/gerencia: nunca bloquear automaticamente", auto=True); return
    open(BLOCK, "a").write(ip + "\n"); audit(action="block_ip", ip=ip, nft=f"nft add rule inet filter input ip saddr {ip} drop", auto=True)
def kill_vpn_session(peer): audit(action="kill_vpn_session", peer=peer, cmd=f"wg set wg0 peer {peer} remove", dryrun=True, auto=True)
def safe_mode(dev):     audit(action="actuator_safe_mode", device=dev, detail="mantem ultimo estado seguro; bloqueia novos comandos remotos", auto=True)
def isolate(dev):       revoke_cert(dev); safe_mode(dev)
HIGH = {"pump_off": "Desligar a bomba (pode afetar o abrigo/escola)", "unlock_all_doors": "Liberar todas as portas"}
def request_approval(action, reason):   # ALTO IMPACTO: nunca executa sozinho
    p = json.load(open(PEND)) if os.path.exists(PEND) else []
    dup = next((q for q in p if q["action"] == action and q["status"] == "pendente"), None)
    if dup: return dup["id"]                                          # nao duplica pedido pendente
    i = len(p) + 1; p.append({"id": i, "action": action, "reason": reason, "status": "pendente", "ts": time.time()}); json.dump(p, open(PEND, "w"), indent=1)
    audit(action="approval_requested", id=i, what=action, auto=False); return i
PLAYBOOK = {"R-VPN-01": [("kill_vpn_session", "peer-suspeito"), ("block_ip", None), ("approval", "pump_off")] , "R-SQLI-01": [("block_ip", None)],
            "R-DEV-01": [("block_ip", None)], "R-ACT-01": [("safe_mode", "bomba-escola"), ("approval", "pump_off")]}
def run(path):
    seen = set()
    for l in open(path):
        a = json.loads(l)
        for step, arg in PLAYBOOK.get(a["rule"], []):
            key = (a["rule"], step, a.get("ip"), arg)
            if key in seen: continue
            seen.add(key)
            if step == "block_ip" and a.get("ip"): block_ip(a["ip"])
            elif step == "kill_vpn_session": kill_vpn_session(arg)
            elif step == "safe_mode": safe_mode(arg)
            elif step == "approval": print(f"[APROVACAO NECESSARIA] #{request_approval(arg, a['rule'] + ': ' + a['why'])} {HIGH.get(arg, arg)}")
def approve(i, by):
    roles = {"coord@vilaaurora.example": "coordenacao", "bruno@vilaaurora.example": "tecnico"}
    if roles.get(by) != "coordenacao": audit(action="approve_denied", id=i, by=by); sys.exit(f"NEGADO: {by} nao tem perfil 'coordenacao'")
    p = json.load(open(PEND)); x = next(q for q in p if q["id"] == i); x["status"] = "aprovado"; x["aprovador"] = by; json.dump(p, open(PEND, "w"), indent=1)
    audit(action=x["action"], approved_by=by, auto=False); print(f"#{i} aprovada por {by}: {x['action']} (executaria agora; dry-run no lab)")
if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("cmd"); ap.add_argument("arg", nargs="?"); ap.add_argument("--by"); a = ap.parse_args()
    if a.cmd == "run": run(a.arg)
    elif a.cmd == "approve": approve(int(a.arg), a.by)
    elif a.cmd == "list": print(open(PEND).read() if os.path.exists(PEND) else "[]")
