# Rede Comunitária Vila Aurora — Infraestrutura Segura e Resiliente (GS 2026.2)

**Equipe:** Lorenzo Costa Jordão (RM 99819) · Thiago Carrasco de Souza (RM 99571) — Turma/Grupo: `[PREENCHER]`
Todos os dados são **sintéticos**. Toda atividade ofensiva roda **apenas em 127.0.0.1 / ambiente próprio** (Lei 12.737/2012; art. 154-A CP).

## Status honesto de cada parte
| Parte | Status |
|---|---|
| PKI própria, mTLS, ACL por CN, revogação (CRL) e rotação | **Testado** (Mosquitto 2.x real) |
| Borda autônoma: regras locais, buffer store-and-forward, reconciliação idempotente | **Testado** + teste de caos (ver `chaos/results/`) |
| Painel vulnerável × corrigido, SQLi antes/depois | **Testado** (`tests/sqli_test.py`) |
| Detecção (4 regras RT-13), SOAR com aprovação humana | **Testado** sobre logs reais/sintéticos |
| Isolation Forest (dados sintéticos) | **Testado**, métricas em `ai/metrics.json` |
| Cadeia de custódia, SHA-256, linha do tempo ATT&CK | **Testado** |
| DKIM (assinatura/verificação) | **Testado**; SPF/DMARC apenas conferidos por texto (sem DNS real) |
| nftables do hub (segmentação) | **Testado com tráfego** em namespaces (`tests/segmentation_test.sh`: 11 conexões, com e sem regras). Regras da borda (`nftables_edge.conf`): só sintaxe |
| WireGuard | Chaves/configs gerados; **túnel não foi estabelecido** aqui (sem módulo de kernel). Roteiro pronto: `docs/GUIA_WIREGUARD.md` + `tests/wireguard_netns_test.sh` (não testado) |
| `docker-compose.yml`, Wazuh (`siem/wazuh_local_rules.xml`) | **NÃO TESTADOS** — precisam ser executados no lab da equipe |
| Gophish (campanha de phishing simulado) | **NÃO EXECUTADO** — roteiro em `docs/GUIA_GOPHISH.md`; `docs/phishing_metrics.py` calcula as métricas reais da exportação (testado com CSV de exemplo) |
| LLM / prompt injection (RT-17) | **Não aplicável**: o protótipo não usa LLM (ver E1) |
| Captura de memória (Volatility), OTA assinado, hardware real | Não feitos (diferenciais) |

## Reproduzir (Linux, Python 3.12, OpenSSL, Mosquitto 2.x, wireguard-tools, nftables)
```bash
pip install -r requirements.txt
bash pki/make_pki.sh                      # CA + certificados (pki/out, NAO versionado)
bash edge/start_broker.sh &               # broker local com mTLS + CRL + ACL
python3 edge/cloud_ingest.py &            # "nuvem" (em producao, atras da VPN)
python3 edge/edge_agent.py &              # no de borda
python3 field/field_sim.py --duration 120 --excursion-at 30 --excursion-len 40
# revogacao:   bash pki/revoke.sh sensor-nivel-escola && kill -HUP $(pgrep -x mosquitto)
# SQLi antes/depois:
python3 db/seed.py /tmp/panel_vuln.db; python3 db/seed.py /tmp/panel_ok.db --pseudo
PANEL_DB=/tmp/panel_vuln.db WEB_LOG=/tmp/web_vuln.log python3 panel/vulneravel/app.py &
PANEL_DB=/tmp/panel_ok.db   WEB_LOG=/tmp/web_ok.log   python3 panel/corrigido/app.py &
python3 tests/sqli_test.py
# deteccao + SOAR + forense:
python3 forensics/reproduce_incident.py
python3 siem/detect.py --out siem/alerts.jsonl vpn:forensics/lab_logs/vpn.jsonl web:forensics/lab_logs/web_painel_vuln.jsonl web:forensics/lab_logs/painel_audit.jsonl mqtt:forensics/lab_logs/mosquitto_trecho.log
python3 soar/soar.py run siem/alerts.jsonl && python3 soar/soar.py list
python3 forensics/timeline.py && python3 forensics/collect_evidence.py --case INC-VA-0712-LAB --collector "SEU NOME" forensics/lab_logs/* siem/alerts.jsonl
python3 ai/anomaly.py
# segmentacao com trafego (root):  sudo bash tests/segmentation_test.sh
# caos (>= 30 min de WAN down; ~35 min total):
BASE=120 DOWN=1830 TAIL=120 python3 chaos/chaos_wan.py
bash vpn/gen_wg.sh; bash mail/make_dns.sh
```
Login do painel corrigido (laboratório): `bruno@vilaaurora.example` / `Senha-Lab-1!` + TOTP do segredo de laboratório em `db/seed.py`.

## Estrutura
`pki/` CA e revogação · `edge/` broker, agente de borda, ingest · `field/` simuladores · `panel/` painel (2 versões) · `siem/` regras de detecção · `soar/` respostas automáticas · `ai/` anomalias · `forensics/` reprodução, custódia, linha do tempo · `chaos/` teste de caos · `vpn/` WireGuard + nftables · `mail/` SPF/DKIM/DMARC · `docs/` documentos.

## Segredos
Nenhuma chave privada é versionada (`.gitignore`: `pki/out/`, `vpn/keys/`, `mail/out/`, `*.key`). O TOTP e a senha dos usuários do painel são **de laboratório**, para dados sintéticos.

## Uso de IA
Claude (Anthropic) foi usado como assistente para gerar código-base, scripts, estrutura dos relatórios e revisão. A equipe é responsável pelo conteúdo, deve executar, entender e poder explicar cada parte.
