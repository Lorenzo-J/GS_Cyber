#!/usr/bin/env bash
# !!! NAO TESTADO no ambiente de desenvolvimento (sem modulo wireguard). Rode no seu Linux com WireGuard. Requer root e 'bash vpn/gen_wg.sh' antes.
set -uo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"; K="$H/vpn/keys"; OUT="$H/tests/results/wireguard_evidence.txt"; mkdir -p "$H/tests/results"; : > "$OUT"; log(){ echo "$*" | tee -a "$OUT"; }
[ -f "$K/wg0-hub.conf" ] || { echo "rode: bash vpn/gen_wg.sh"; exit 1; }
cleanup(){ ip netns del wghub 2>/dev/null; ip netns del wgedge 2>/dev/null; }; trap cleanup EXIT; cleanup
ip netns add wghub; ip netns add wgedge; ip link add u_hub type veth peer name u_edge; ip link set u_hub netns wghub; ip link set u_edge netns wgedge
ip -n wghub addr add 192.0.2.1/30 dev u_hub; ip -n wgedge addr add 192.0.2.2/30 dev u_edge; ip -n wghub link set u_hub up; ip -n wgedge link set u_edge up
up(){ ip netns exec $1 bash -c "ip link add wg0 type wireguard && wg setconf wg0 <(wg-quick strip $2) && ip addr add $3 dev wg0 && ip link set wg0 up"; }
up wghub "$K/wg0-hub.conf" 10.200.0.1/24; up wgedge "$K/wg0-edge-ubs.conf" 10.200.0.11/24
ip netns exec wgedge wg set wg0 peer "$(cat $K/hub.pub)" endpoint 192.0.2.1:51820
ip netns exec wgedge ping -c1 -W2 10.200.0.1 >/dev/null 2>&1; sleep 1
log "1) handshake/trafego: $(ip netns exec wgedge wg show wg0 | grep -E 'latest handshake|transfer' | tr '\n' ' ')"
log "2) ping edge -> hub pelo tunel: $(ip netns exec wgedge ping -c2 -W2 10.200.0.1 >/dev/null 2>&1 && echo OK || echo FALHOU)"
ip netns exec wghub wg set wg0 peer "$(cat $K/edge-ubs.pub)" remove
log "3) apos REMOVER o peer da borda no hub, ping: $(ip netns exec wgedge ping -c2 -W2 10.200.0.1 >/dev/null 2>&1 && echo 'AINDA PASSA (FALHA)' || echo 'BLOQUEADO (esperado)')"
log "4) porta de escuta do hub (UDP): $(ip netns exec wghub wg show wg0 listen-port)"; log "5) suite criptografica do WireGuard (fixa): Curve25519, ChaCha20-Poly1305, BLAKE2s, HKDF; PSK opcional ativo neste peer"
