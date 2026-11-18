#!/usr/bin/env bash
# Rotacao de credencial: revoga o cert antigo, apaga o par de chaves e emite um novo. Uso: rotate.sh <cn>
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; OUT="${PKI_OUT:-$D/out}"; cn="$1"
"$D/revoke.sh" "$cn" || true; rm -f "$OUT/devices/$cn".{key,csr,crt,ext}
PKI_OUT="$OUT" bash "$D/make_pki.sh" >/dev/null
echo "Rotacionado $cn"
