#!/usr/bin/env bash
# Teste de segmentacao COM TRAFEGO usando network namespaces (precisa de root, iproute2, nftables e python3).
# Roda a bateria SEM regras (linha de base: tudo deve passar) e COM vpn/nftables.conf (so o permitido passa).
set -uo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"; OUT="$H/tests/results/segmentation_evidence.txt"; mkdir -p "$H/tests/results"; : > "$OUT"
log(){ echo "$*" | tee -a "$OUT"; }
cleanup(){ for p in $(cat /tmp/seg_pids 2>/dev/null); do kill $p 2>/dev/null; done; for n in gw ops db vpn; do ip netns del $n 2>/dev/null; done; rm -f /tmp/seg_pids; }
trap cleanup EXIT; cleanup
for n in gw ops db vpn; do ip netns add $n; ip -n $n link set lo up; done
pair(){ ip link add $1 type veth peer name $2; ip link set $1 netns gw; ip link set $2 netns $3; ip -n gw link set $1 up; ip -n $3 link set $2 up; }
pair g_ops ops0 ops; pair g_db db0 db; pair g_vpn vpn0 vpn
ip -n gw addr add 10.20.0.1/24 dev g_ops; ip -n gw addr add 10.40.0.1/24 dev g_db; ip -n gw addr add 10.200.0.1/24 dev g_vpn
for a in 10.20.0.10 10.20.0.20 10.20.0.50; do ip -n ops addr add $a/24 dev ops0; done; ip -n ops route add default via 10.20.0.1
ip -n db addr add 10.40.0.5/24 dev db0; ip -n db route add default via 10.40.0.1
for a in 10.200.0.11 10.200.0.100 10.200.0.77; do ip -n vpn addr add $a/24 dev vpn0; done; ip -n vpn route add default via 10.200.0.1
ip netns exec gw sysctl -qw net.ipv4.ip_forward=1
SRV='import socket,sys,threading,time
def l(ip,p):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((ip,p)); s.listen(50)
    while True: c,_=s.accept(); c.close()
for a in sys.argv[1:]:
    ip,p=a.split(":"); threading.Thread(target=l,args=(ip,int(p)),daemon=True).start()
time.sleep(600)'
ip netns exec ops python3 -c "$SRV" 10.20.0.10:443 10.20.0.20:8090 & echo $! >> /tmp/seg_pids
ip netns exec db python3 -c "$SRV" 10.40.0.5:5432 & echo $! >> /tmp/seg_pids
ip netns exec gw python3 -c "$SRV" 0.0.0.0:22 & echo $! >> /tmp/seg_pids
sleep 1
try(){ ip netns exec $1 python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(1.5); s.bind(('$2',0))
try: s.connect(('$3',$4)); print('PASSA')
except Exception: print('BLOQUEADO')"; }
# nome | ns origem | ip origem | ip destino | porta | esperado COM regras
TESTS=(
"borda(.11) -> ingest:8090|vpn|10.200.0.11|10.20.0.20|8090|PASSA"
"borda(.11) -> painel:443|vpn|10.200.0.11|10.20.0.10|443|BLOQUEADO"
"borda(.11) -> banco:5432|vpn|10.200.0.11|10.40.0.5|5432|BLOQUEADO"
"peer desconhecido(.77) -> ingest:8090|vpn|10.200.0.77|10.20.0.20|8090|BLOQUEADO"
"admin(.100) -> banco:5432|vpn|10.200.0.100|10.40.0.5|5432|PASSA"
"painel(.10) -> banco:5432|ops|10.20.0.10|10.40.0.5|5432|PASSA"
"operador(.50) -> banco:5432|ops|10.20.0.50|10.40.0.5|5432|BLOQUEADO"
"ingest(.20) -> banco:5432|ops|10.20.0.20|10.40.0.5|5432|BLOQUEADO"
"admin(.100) -> hub SSH:22|vpn|10.200.0.100|10.200.1.1|22|PASSA"
"peer desconhecido(.77) -> hub SSH:22|vpn|10.200.0.77|10.200.0.1|22|BLOQUEADO"
"borda(.11) -> hub SSH:22|vpn|10.200.0.11|10.200.0.1|22|BLOQUEADO")
run(){ local fail=0; for t in "${TESTS[@]}"; do IFS='|' read -r nm ns sip dip port exp <<<"$t"; [ "$dip" = 10.200.1.1 ] && dip=10.200.0.1
  r=$(try $ns $sip $dip $port); [ "$1" = base ] && want=PASSA || want=$exp
  [ "$r" = "$want" ] && v=OK || { v="FALHA"; fail=$((fail+1)); }; log "$(printf '%-44s' "$nm") obtido=$r esperado=$want  [$v]"; done; return $fail; }
log "=== A) LINHA DE BASE: SEM regras nftables (tudo deve passar) ==="; run base; fb=$?
ip netns exec gw nft -f "$H/vpn/nftables.conf" || { log "ERRO ao carregar nftables"; exit 2; }
log ""; log "=== B) COM vpn/nftables.conf (so o permitido deve passar) ==="; run rules; fr=$?
log ""; log "Contadores de pacotes descartados (log/counter do nftables):"; ip netns exec gw nft list ruleset | grep -E "counter packets" | sed 's/^ */  /' | tee -a "$OUT"
log ""; log "RESUMO: linha de base falhas=$fb | com regras falhas=$fr  (0 = segmentacao efetiva conforme o desenho)"
exit $((fb+fr))
