#!/usr/bin/env bash
# Revoga o certificado de um dispositivo e regenera a CRL. Uso: revoke.sh <cn>
set -euo pipefail
OUT="${PKI_OUT:-$(cd "$(dirname "$0")" && pwd)/out}"; cd "$OUT"; cn="$1"
openssl ca -config openssl-ca.cnf -revoke "devices/$cn.crt" -crl_reason keyCompromise 2>&1 | tail -1 || true
openssl ca -config openssl-ca.cnf -gencrl -out crl.pem 2>/dev/null
echo "[$(date -u +%FT%TZ)] REVOGADO $cn" | tee -a revocations.log
