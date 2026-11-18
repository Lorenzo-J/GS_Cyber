#!/usr/bin/env bash
set -euo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"; export PKI="${PKI:-$H/pki/out}"; export ACL="$H/edge/acl.conf"
mkdir -p "$H/edge/data"; export LOG="$H/edge/data/mosquitto.log"; : > "$LOG"
envsubst < "$H/edge/mosquitto.conf" > "$H/edge/data/mosquitto.rendered.conf"
# Em lab rodando como root (sandbox/CI) o Mosquitto tentaria virar o usuario 'mosquitto' e nao leria a chave.
[ "$(id -u)" = 0 ] && echo "user root" >> "$H/edge/data/mosquitto.rendered.conf"
echo $$ > "$H/edge/data/broker.pid"
exec mosquitto -c "$H/edge/data/mosquitto.rendered.conf"
