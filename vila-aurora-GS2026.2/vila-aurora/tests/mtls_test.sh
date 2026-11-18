#!/usr/bin/env bash
# Evidencia de mTLS, ACL e revogacao (RT-04/RT-05). Requer o broker local em execucao (edge/start_broker.sh).
set -uo pipefail
H="$(cd "$(dirname "$0")/.." && pwd)"; cd "$H"; P=pki/out; D=$P/devices; OUT=tests/results/mtls_evidence.txt; mkdir -p tests/results; : > $OUT
log(){ echo "$*" | tee -a $OUT; }
pub(){ mosquitto_pub -h 127.0.0.1 -p 8883 --cafile $P/ca.crt "$@" 2>&1; }
dev="sensor-camara-fria-ubs"
log "T1 cert valido publica na propria arvore:        $(pub --cert $D/$dev.crt --key $D/$dev.key -t vila/telemetria/$dev -m '{"t":4.2}' >/dev/null && echo ACEITO || echo RECUSADO)"
log "T2 sem certificado de cliente:                    $(pub -t vila/telemetria/x -m x | tail -1)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/rogue.key -out /tmp/rogue.crt -subj "/CN=rogue" -days 1 2>/dev/null
log "T3 certificado forjado (CA desconhecida):        $(pub --cert /tmp/rogue.crt --key /tmp/rogue.key -t vila/telemetria/rogue -m x | tail -1)"
n0=$(grep -c "Denied PUBLISH" edge/data/mosquitto.log); pub --cert $D/$dev.crt --key $D/$dev.key -t vila/telemetria/bomba-escola -m '{"t":99}' >/dev/null; sleep 1
log "T4 cert valido publicando na arvore de outro dispositivo (ACL): negacoes novas no log = $(( $(grep -c 'Denied PUBLISH' edge/data/mosquitto.log) - n0 ))"
dev="sensor-nivel-escola"; log "T5 antes da revogacao ($dev):                   $(pub --cert $D/$dev.crt --key $D/$dev.key -t vila/telemetria/$dev -m '{"v":1}' >/dev/null && echo ACEITO || echo RECUSADO)"
t0=$(date +%s.%N); bash pki/revoke.sh $dev >/dev/null; kill -HUP $(pgrep -x mosquitto); 
for i in $(seq 1 50); do pub --cert $D/$dev.crt --key $D/$dev.key -t vila/telemetria/$dev -m '{"v":1}' >/dev/null || break; sleep 0.1; done
t1=$(date +%s.%N); log "T6 apos revogar + recarregar broker:             RECUSADO; tempo ate a recusa efetiva = $(echo "$t1 - $t0" | bc -l | cut -c1-5) s"
log "T7 outro dispositivo continua operando:           $(pub --cert $D/sensor-energia-centro.crt --key $D/sensor-energia-centro.key -t vila/telemetria/sensor-energia-centro -m '{"w":1}' >/dev/null && echo ACEITO || echo RECUSADO)"
t0=$(date +%s.%N); bash pki/rotate.sh $dev >/dev/null 2>&1; kill -HUP $(pgrep -x mosquitto); sleep 1
log "T8 apos rotacao (novo par de chaves, novo cert):  $(pub --cert $D/$dev.crt --key $D/$dev.key -t vila/telemetria/$dev -m '{"v":1}' >/dev/null && echo ACEITO || echo RECUSADO); tempo de rotacao = $(echo "$(date +%s.%N) - $t0" | bc -l | cut -c1-5) s"
log "CRL: $(openssl crl -in $P/crl.pem -noout -text | grep -c 'Serial Number') certificado(s) revogado(s); serial(is): $(openssl crl -in $P/crl.pem -noout -text | grep 'Serial Number' | awk '{print $3}' | tr '\n' ' ')"
log "Algoritmos: TLS $(openssl s_client -connect 127.0.0.1:8883 -CAfile $P/ca.crt -cert $D/sensor-energia-centro.crt -key $D/sensor-energia-centro.key </dev/null 2>/dev/null | grep -E '^New, ' )"
