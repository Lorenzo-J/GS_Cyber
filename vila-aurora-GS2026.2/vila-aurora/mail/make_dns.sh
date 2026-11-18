#!/usr/bin/env bash
# Gera chave DKIM (selector s2026) e imprime os registros DNS do dominio ficticio. Chave privada fica em mail/out (gitignored).
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"; O="$D/out"; mkdir -p "$O"; DOM="vilaaurora.example"; SEL="s2026"
[ -f "$O/dkim.key" ] || openssl genrsa -out "$O/dkim.key" 2048 2>/dev/null
PUB=$(openssl rsa -in "$O/dkim.key" -pubout -outform DER 2>/dev/null | openssl base64 -A)
cat > "$D/dns_records.txt" <<REC
; Dominio FICTICIO do projeto: $DOM (TLD .example reservado pela RFC 2606 - nao resolve na internet)
$DOM.                      IN TXT "v=spf1 ip4:198.51.100.25 -all"
$SEL._domainkey.$DOM.      IN TXT "v=DKIM1; k=rsa; p=$PUB"
_dmarc.$DOM.               IN TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@$DOM; adkim=s; aspf=s; fo=1"
REC
cat "$D/dns_records.txt" | cut -c1-150
