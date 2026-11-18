#!/usr/bin/env bash
# Gera chaves WireGuard (por peer, com PSK) e configs hub-and-spoke. Chaves em vpn/keys (gitignored). Nada de segredo no Git.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; K="$D/keys"; mkdir -p "$K"; umask 077
gen(){ [ -f "$K/$1.key" ] || { wg genkey | tee "$K/$1.key" | wg pubkey > "$K/$1.pub"; }; }
for p in hub edge-ubs edge-escola admin-laptop; do gen $p; done; [ -f "$K/psk-edge-ubs" ] || wg genpsk > "$K/psk-edge-ubs"
cat > "$K/wg0-hub.conf" <<CONF
[Interface]
Address = 10.200.0.1/24
ListenPort = 51820
PrivateKey = $(cat "$K/hub.key")
[Peer]   # no de borda da UBS: so enxerga a rede IoT/ingest
PublicKey = $(cat "$K/edge-ubs.pub")
PresharedKey = $(cat "$K/psk-edge-ubs")
AllowedIPs = 10.200.0.11/32
[Peer]   # no de borda da escola
PublicKey = $(cat "$K/edge-escola.pub")
AllowedIPs = 10.200.0.12/32
[Peer]   # administrador (acesso admin SOMENTE via VPN; MFA aplicado no bastion/painel, WireGuard nao tem MFA nativo)
PublicKey = $(cat "$K/admin-laptop.pub")
AllowedIPs = 10.200.0.100/32
CONF
cat > "$K/wg0-edge-ubs.conf" <<CONF
[Interface]
Address = 10.200.0.11/24
PrivateKey = $(cat "$K/edge-ubs.key")
[Peer]
PublicKey = $(cat "$K/hub.pub")
PresharedKey = $(cat "$K/psk-edge-ubs")
Endpoint = hub.vilaaurora.example:51820
AllowedIPs = 10.200.0.1/32
PersistentKeepalive = 25
CONF
echo "WireGuard: chaves e configs em $K (cifras: Curve25519, ChaCha20-Poly1305, BLAKE2s)"; ls "$K"
