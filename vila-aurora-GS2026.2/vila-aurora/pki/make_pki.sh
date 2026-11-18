#!/usr/bin/env bash
# PKI do projeto Vila Aurora (CA propria + certs por dispositivo). Tudo gerado por script, nada versionado.
set -euo pipefail
OUT="${PKI_OUT:-$(cd "$(dirname "$0")" && pwd)/out}"; mkdir -p "$OUT/devices" "$OUT/newcerts"; cd "$OUT"
[ -f ca.key ] || { openssl genrsa -out ca.key 4096 2>/dev/null
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 -subj "/O=Vila Aurora/CN=Vila Aurora Root CA (LAB)" -out ca.crt; }
touch index.txt; [ -f crlnumber ] || echo 1000 > crlnumber; [ -f serial ] || echo 1000 > serial
cat > openssl-ca.cnf <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $OUT
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days = 7
policy = pol
unique_subject = no
[ pol ]
commonName = supplied
CNF
issue() { # issue <cn> <kind: server|client> [SAN]
  local cn="$1" kind="$2" san="${3:-DNS:$1}"
  [ -f "devices/$cn.key" ] && return 0
  openssl genrsa -out "devices/$cn.key" 2048 2>/dev/null
  openssl req -new -key "devices/$cn.key" -subj "/O=Vila Aurora/CN=$cn" -out "devices/$cn.csr"
  printf "basicConstraints=CA:FALSE\nextendedKeyUsage=%s\nsubjectAltName=%s\n" \
    "$([ "$kind" = server ] && echo serverAuth || echo clientAuth)" "$san" > "devices/$cn.ext"
  openssl ca -batch -config openssl-ca.cnf -notext -days 365 -in "devices/$cn.csr" -out "devices/$cn.crt" -extfile "devices/$cn.ext" 2>/dev/null
}
issue edge-ubs server "DNS:edge-ubs,DNS:broker-edge,DNS:localhost,IP:127.0.0.1"
for d in edge-agent sensor-camara-fria-ubs sensor-nivel-escola bomba-escola sensor-energia-centro; do issue "$d" client; done
openssl ca -config openssl-ca.cnf -gencrl -out crl.pem 2>/dev/null
echo "PKI ok em $OUT"; ls devices/*.crt
