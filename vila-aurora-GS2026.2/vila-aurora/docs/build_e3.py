import sys, os, re, json, collections; sys.path.insert(0, os.path.dirname(__file__))
from lib import *
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
MF = f"{H}/chaos/results/metrics.json"
if not os.path.exists(MF): sys.exit("ABORTADO: chaos/results/metrics.json nao existe (teste de caos nao concluiu). Nao ha como gerar o E3 sem metricas medidas.")
M = J("chaos/results/metrics.json"); SM = J("chaos/results/samples.json"); AI = J("ai/metrics.json"); MT = J("siem/mttd_live.json")["mttd_s"]
import glob
rd = lambda p: open(f"{H}/{p}").read()
PH = [json.load(open(f)) for f in sorted(glob.glob(f"{H}/tests/results/phishing_metrics_*.json"))]
SEG = open(f"{H}/tests/results/segmentation_evidence.txt").read() if os.path.exists(f"{H}/tests/results/segmentation_evidence.txt") else None
WG = open(f"{H}/tests/results/wireguard_evidence.txt").read() if os.path.exists(f"{H}/tests/results/wireguard_evidence.txt") else None
if M["wan_down_s"] < 1800: sys.exit(f"ABORTADO: queda do WAN de {M['wan_down_s']} s < 1800 s exigidos (RT-23).")
# grafico do caos
sm, pr = SM["samples"], SM["probes"]; t = [x["t"] for x in sm]; ph = [x["phase"] for x in sm]
d0 = next(x["t"] for x in sm if x["phase"] == "wan_down"); u0 = next(x["t"] for x in sm if x["phase"] == "wan_up")
fig, ax = plt.subplots(3, 1, figsize=(8.5, 7), sharex=True)
for a in ax: a.axvspan(d0, u0, color="#ffd9d9", alpha=.6)
ax[0].plot(t, [x["rx"] for x in sm], label="leituras recebidas na borda (acum.)", color="#0b5d3b"); ax[0].set_ylabel("leituras")
a2 = ax[0].twinx(); a2.plot(t, [x["tx_bytes"] / 1024 for x in sm], color="#b25c00", label="KiB enviados à nuvem (acum.)"); a2.set_ylabel("KiB")
ax[0].legend(loc="upper left", fontsize=7); a2.legend(loc="lower right", fontsize=7); ax[0].set_title("Borda continua recebendo; o envio à nuvem pausa na queda do WAN (faixa rosa) e retoma depois", fontsize=8)
ax[1].plot(t, [x["edge_cpu"] for x in sm], label="CPU agente de borda (%)", color="#1a5fa0"); a3 = ax[1].twinx(); a3.plot(t, [x["edge_rss_mb"] for x in sm], color="#7b2d8b", label="RSS (MB)"); ax[1].set_ylabel("CPU %"); a3.set_ylabel("MB"); ax[1].legend(loc="upper left", fontsize=7); a3.legend(loc="upper right", fontsize=7)
ax[2].step([p["t"] for p in pr], [int(p["local"]) for p in pr], where="post", label="broker local (mTLS)", color="#0b5d3b"); ax[2].step([p["t"] for p in pr], [int(p["cloud"]) * 0.9 for p in pr], where="post", label="serviço de nuvem", color="#b00020")
ax[2].set_ylim(-.1, 1.2); ax[2].set_yticks([0, 1]); ax[2].set_yticklabels(["fora", "no ar"]); ax[2].legend(fontsize=7, loc="center right"); ax[2].set_xlabel("tempo (s)")
plt.tight_layout(); plt.savefig(f"{H}/docs/img/caos.png", dpi=150); plt.close()
mt = open(f"{H}/tests/results/mtls_evidence.txt").read() if os.path.exists(f"{H}/tests/results/mtls_evidence.txt") else "(mtls_test.sh nao executado)"
rev = re.search(r"tempo ate a recusa efetiva = ([\d.]+) s", mt); rev_t = rev.group(1) + " s" if rev else "n/d"
first_mttd = M["mttd_alarme_local_s"][0] if M["mttd_alarme_local_s"] else None
bpr = M["buffer_db_bytes"] / max(1, M["leituras_no_buffer_da_borda"]); rps = M["leituras_no_buffer_da_borda"] / M["duracao_total_s"]; dias = (8e9 / (bpr * rps)) / 86400
al = [json.loads(l) for l in open(f"{H}/siem/alerts.jsonl")]; rc = collections.Counter(a["rule"] for a in al)
s = cover("E3", "Relatório de Testes de Segurança")
s += [P("1. Ambiente e método", "h1"), P("Host único Linux (1 vCPU, ≈4 GB RAM), Python 3.12, OpenSSL 3.0, Mosquitto 2.x, nftables, wireguard-tools. Dispositivos simulados por processos Python, cada um com certificado próprio. Alvos <b>somente 127.0.0.1</b>. Dados sintéticos. Scripts e evidências brutas estão no repositório (E2): tests/, chaos/results/, siem/, ai/. Cada seção indica o status: <b>Testado</b>, <b>Parcial</b> ou <b>Não executado</b>."),
 P("2. SQL Injection — antes e depois (RT-08) — Testado", "h1"), P("Payloads clássicos contra o painel vulnerável (concatenação de strings, erro detalhado) e contra o corrigido (login com senha + TOTP). A tautologia inicial <i>x' OR '1'='1</i> <b>não funcionou</b> dentro de um LIKE com % e foi substituída por <i>x' OR 1=1 --</i>; o critério de “vazou” inclui “retornou todos os registros”."), code(rd("tests/results/sqli_evidence.txt")),
 P("<b>Leitura:</b> a versão vulnerável vazou dados em 3 de 4 payloads (o quarto expôs o erro SQL detalhado, falha de vazamento de informação). A corrigida bloqueou 4 de 4 e, isolando a causa raiz (mesma consulta parametrizada, sem WAF e sem validação), os 4 payloads retornam 0 linhas: a correção está na parametrização, não no filtro. WAF e validação são camadas adicionais. <b>Limite:</b> o banco do protótipo é SQLite; o privilégio mínimo (db/postgres_roles.sql) é desenho, não teste."),
 P("3. mTLS, ACL por certificado, revogação e rotação (RT-04, RT-05) — Testado", "h1"), code(mt),
 P(f"Tempo de revogação efetiva medido: <b>{rev_t}</b> (revogar + gerar CRL + recarregar o broker). Em produção a CRL deve ser regenerada por cron (validade 7 dias) e o broker recarregado ao revogar."),
 P("4. VPN e segmentação (RT-06, RT-07) — " + ("Testado" if (SEG and WG) else "Parcial"), "h1"),
 P("<b>Segmentação com tráfego real (namespaces de rede + nftables):</b> a mesma bateria de 11 conexões foi executada sem regras (linha de base: todas passam) e com vpn/nftables.conf (só as permitidas passam). Isso comprova o isolamento do desenho entre peers da VPN, ops, banco e o próprio hub." if SEG else "<b>Segmentação:</b> regras com sintaxe validada, sem teste de tráfego."),
 *([code(SEG)] if SEG else []),
 *B(["<b>Tunel WireGuard:</b> " + ("testado: ver evidência abaixo." if WG else "<b>não foi estabelecido</b> no ambiente de desenvolvimento (sem módulo de kernel). Há roteiro pronto (docs/GUIA_WIREGUARD.md, tests/wireguard_netns_test.sh) para executar em Linux com WireGuard; até lá, não há evidência de túnel funcionando."),
    "<b>Regras do nó de borda</b> (vpn/nftables_edge.conf, IoT → broker 8883): sintaxe validada; <b>não exercitadas com tráfego</b>.",
    "<b>Achado de projeto:</b> ao escrever o teste percebi que a regra IoT→broker estava no hub, mas esse fluxo é local da borda; foi movida para vpn/nftables_edge.conf.",
    "<b>MFA:</b> o WireGuard não possui MFA nativo. O MFA (TOTP) está implementado e testado no painel. Para acesso administrativo remoto, recomenda-se bastion/ZTNA com MFA; <b>isso é projeto, não teste</b>. TOTP é vulnerável a phishing em tempo real: para a coordenação recomenda-se FIDO2/WebAuthn."]),
 *([code(WG)] if WG else []),
 P("5. SPF, DKIM e DMARC (RT-10) — Parcial", "h1"), code(rd("mail/dns_records.txt")[:1500].replace("p=MIIB", "p=MIIB")), code(rd("tests/results/dkim_evidence.txt")),
 P("6. Campanha de phishing simulado (RT-11) — " + ("Executada em lab" if PH else "NÃO EXECUTADA"), "h1"),
 *([P("Campanha em ambiente isolado (Gophish + servidor SMTP de laboratório), <b>somente contra contas fictícias criadas pela equipe</b>, sem coleta de credenciais reais (a senha digitada não é capturada). <b>Os alvos são integrantes da equipe agindo como voluntários</b>; portanto as taxas refletem o comportamento da equipe e não o de voluntários reais. Números calculados por docs/phishing_metrics.py a partir da exportação do Gophish.", "p"),
    T([["Métrica"] + [x["cenario"] for x in PH], ["E-mails enviados"] + [x["enviados"] for x in PH], ["Taxa de abertura (%)"] + [x["taxa_abertura_pct"] for x in PH], ["Taxa de clique (%)"] + [x["taxa_clique_pct"] for x in PH], ["Taxa de submissão (%)"] + [x["taxa_submissao_pct"] for x in PH], ["Taxa de reporte (%)"] + [x["taxa_reporte_pct"] for x in PH], ["Tempo mediano até o reporte (s)"] + [x["tempo_mediano_ate_reporte_s"] for x in PH]], [6] + [10.4 / len(PH)] * len(PH))] if PH else
   [P("<b>Não há métricas reais de campanha neste relatório.</b> O Gophish não foi executado no ambiente de desenvolvimento; inventar números seria fraude acadêmica. Roteiro em docs/GUIA_GOPHISH.md e cálculo em docs/phishing_metrics.py; ao executar, rode build_e3.py de novo e esta tabela é preenchida automaticamente.", "warn"),
    T([["Métrica", "Cenário 1", "Cenário 2", "Cenário 3"]] + [[m] + ["[PREENCHER]"] * 3 for m in ["E-mails enviados", "Taxa de abertura", "Taxa de clique", "Taxa de submissão de credencial", "Taxa de reporte", "Tempo mediano até o reporte"]], [6, 3.6, 3.6, 3.6])]),
 *B(["<b>Plano:</b> 3 cenários (aviso “da prefeitura” gerado por IA, atualização de acesso ao painel, pedido urgente de liberação de acesso).", "<b>Consentimento:</b> apenas integrantes da equipe, com registro escrito; voz clonada somente de quem consentir por escrito e sempre identificada como sintética."]),
 P("Conscientização adaptada a voluntários (linguagem simples)", "h2"),
 *B(["<b>Oficina de 40 minutos</b>, presencial, com exemplos reais em português e cartaz A4 na parede do Centro Comunitário.", "<b>3 perguntas antes de clicar:</b> Eu estava esperando isso? Tem pressa ou ameaça? Pede senha, código ou liberar acesso?", "<b>Regra de ouro:</b> ninguém da prefeitura pede senha por e-mail, WhatsApp ou áudio. Se pedir, desligue e ligue de volta para o número que você já tinha.",
    "<b>Palavra-código</b> combinada pessoalmente entre coordenação e prefeitura para pedidos urgentes; sem ela, não se muda acesso nem a bomba.", "<b>Regra de duas pessoas</b> para ações de alto impacto. Reportar sem medo: canal simples com a coordenação, sem punição."]),
 P("7. Detecção e resposta (RT-12, RT-13, RT-15) — Testado (logs reais e sintéticos)", "h1"),
 T([["Regra", "O que detecta", "Alertas no incidente reproduzido", "MTTD ao vivo"], ["R-VPN-01", "Login VPN fora da lista de IPs, fora do horário ou sem MFA", str(rc["R-VPN-01"]), "n/d (registro sintético)"], ["R-SQLI-01/02", "Padrões de SQLi e sondas de aspas", f'{rc["R-SQLI-01"]} + {rc["R-SQLI-02"]}', f'{MT["R-SQLI-01"]["media"]} s (máx {MT["R-SQLI-01"]["max"]} s; n={MT["R-SQLI-01"]["n"]})'],
  ["R-DEV-01/02", "Conexão MQTT sem certificado válido / violação de ACL", str(rc["R-DEV-01"]), f'{MT["R-DEV-01"]["media"]} s (máx {MT["R-DEV-01"]["max"]} s; n={MT["R-DEV-01"]["n"]}); resolução do log 1 s'], ["R-ACT-01", "Comando de atuador fora do perfil/horário", str(rc["R-ACT-01"]), "n/d (registro sintético)"]], [2.4, 6.4, 3.2, 5]),
 P("O motor equivalente em Wazuh (siem/wazuh_local_rules.xml) está escrito e com XML bem formado, mas <b>não foi executado</b> em um Wazuh real. Ao revisar a primeira versão, a regra de SQLi <b>não detectava</b> a sonda de aspas isolada e a deduplicação fundia duas rejeições TLS em um alerta; ambos foram corrigidos e re-testados. O SOAR executa ações de baixo risco automaticamente, enfileira o <i>desligar a bomba</i> para aprovação, <b>negou</b> aprovação de perfil não-coordenação e recusa bloquear loopback/redes privadas."),
 P("8. IA defensiva — Isolation Forest (RT-16) — Testado", "h1"),
 T([["Limiar", "Precisão", "Revocação", "F1", "Falsos positivos", "Taxa FP"], ["Padrão do sklearn", AI["limiar_padrao"]["precisao"], AI["limiar_padrao"]["revocacao"], AI["limiar_padrao"]["f1"], AI["limiar_padrao"]["falsos_positivos"], AI["limiar_padrao"]["taxa_falso_positivo"]],
  ["Escolhido na validação", AI["limiar_ajustado_na_validacao"]["precisao"], AI["limiar_ajustado_na_validacao"]["revocacao"], AI["limiar_ajustado_na_validacao"]["f1"], AI["limiar_ajustado_na_validacao"]["falsos_positivos"], AI["limiar_ajustado_na_validacao"]["taxa_falso_positivo"]]], [4, 2.4, 2.4, 2, 3.2, 3]),
 P(f"Treino só com {AI['amostras_treino(normais)']} amostras normais; teste com {AI['amostras_teste']} amostras e {AI['anomalias_reais_no_teste']} anomalias rotuladas; o limiar foi escolhido num conjunto de validação separado (para não vazar o teste). <b>Resultado modesto:</b> com precisão ≈ {AI['limiar_ajustado_na_validacao']['precisao']}, cerca de 4 em cada 10 alertas seriam falsos. Os dados são sintéticos, então o desempenho real tende a ser pior; é um detector auxiliar, e o alarme da câmara fria continua sendo a regra determinística local."),
 PageBreak(), P("9. Teste de caos e métricas (RT-22, RT-23) — Testado", "h1"),
 P(f"Queda do WAN emulada <b>parando o serviço de nuvem</b> por <b>{M['wan_down_s']} s</b> ({M['wan_down_s'] / 60:.1f} min), com {M['baseline_s']} s de baseline e {M['tail_s']} s após a restauração. Durante a queda houve excursão de temperatura da câmara fria, e os sensores continuaram publicando. Evidências: chaos/results/ (timeline.log, metrics.json, samples.json)."), Image(f"{H}/docs/img/caos.png", width=15.5 * cm, height=12.7 * cm),
 T([["Indicador (RT-22)", "Valor medido", "Como foi medido / observação"],
  ["Disponibilidade do serviço local", f'{M["disponibilidade_local_pct"]} % (durante a queda: {M["disponibilidade_local_durante_wan_down_pct"]} %)', "Sondas a cada 5 s: handshake mTLS no broker local"],
  ["Disponibilidade do serviço de nuvem", f'{M["disponibilidade_nuvem_pct"]} %', "Sondas TCP; reflete a queda induzida, não a disponibilidade real de um provedor"],
  ["MTTD do alarme local da câmara fria", f"{first_mttd} s", "Da 1ª leitura fora da faixa até o alarme; mínimo teórico 4 s (3 leituras consecutivas a cada 2 s)"],
  ["MTTD das regras do SIEM", f'{MT["R-SQLI-01"]["media"]} s (SQLi); {MT["R-DEV-01"]["media"]} s (dispositivo)', "Modo tempo real, logs locais, sondagem de 0,25 s"],
  ["MTTR: reconciliação após volta do link", f'{M["tempo_reconciliacao_s"]} s ({M["backlog_reconciliado_linhas"]} linhas no 1º lote)', "Da volta do serviço até o 1º lote aceito; lotes de até 500 linhas"],
  ["MTTR: revogação de dispositivo comprometido", rev_t, "Revogar + CRL + recarregar o broker (tests/mtls_test.sh)"],
  ["Tempo de operação autônoma sem internet", f'{M["wan_down_s"]} s medidos sem interrupção do serviço local', f"Capacidade do buffer: ≈ {bpr:.0f} B/leitura a {rps:.2f} leituras/s; reservando 8 GB, ≈ {dias:.0f} dias (extrapolação, <b>não medida</b>)"],
  ["Leituras publicadas / no buffer / na nuvem", f'{M["leituras_publicadas_pelos_sensores"]} / {M["leituras_no_buffer_da_borda"]} / {M["leituras_na_nuvem"]}', "Sensor→borda e borda→nuvem"],
  ["Perda sensor→borda; perda na reconciliação", f'{M["perda_sensor_para_borda"]}; {M["perda_na_reconciliacao(borda-nuvem)"]}', f'Duplicatas descartadas por idempotência: {M["duplicatas_descartadas_idempotencia"]}'],
  ["Alarmes locais / comandos de bomba na queda", f'{M["alarmes_durante_wan_down"]} / {M["comandos_bomba_durante_wan_down"]}', "O alarme é reemitido a cada 60 s enquanto a condição persiste"],
  ["CPU do agente de borda (média / máx)", f'{M["edge_cpu_medio_pct"]} % / {M["edge_cpu_max_pct"]} %', "psutil; host de 1 vCPU compartilhado com o simulador"],
  ["Memória do agente / broker (RSS máx)", f'{M["edge_rss_max_mb"]} MB / {M["broker_rss_max_mb"]} MB', "psutil"],
  ["CPU do broker (média)", f'{M["broker_cpu_medio_pct"]} %', "psutil"],
  ["Banda borda→nuvem", f'{M["banda_borda_para_nuvem_bytes"] / 1024:.1f} KiB no teste ({M["banda_borda_para_nuvem_bytes"] / M["duracao_total_s"]:.1f} B/s)', "Corpo HTTP dos lotes, sem cabeçalhos TCP/IP"],
  ["Energia do nó de borda", "<b>NÃO MEDIDA</b>", "Ambiente simulado, sem medidor de tomada. Medir em Raspberry Pi real; não há estimativa confiável aqui"]], [4.6, 4.8, 7.6]),
 P("Análise crítica dos resultados", "h2"),
 *B(["<b>O que o teste prova:</b> a borda continua recebendo, aplicando regras e armazenando durante a queda, e reconcilia sem perda nem duplicação ao voltar. O mecanismo store-and-forward com chave (borda, seq) funciona.",
    "<b>O que o teste NÃO prova:</b> a queda foi emulada parando um processo local, não cortando um caminho de rede. Não exercita timeouts de TCP, falhas de DNS, perda de pacotes nem instabilidade de 4G; a perda sensor→borda de 0 ocorre em loopback e pode ser maior em Wi-Fi/LoRa. Recomenda-se QoS 1 nos sensores reais.",
    "<b>Limites de método:</b> 1 vCPU compartilhado; o CPU medido do agente não representa um Raspberry Pi; sem hardware real; disponibilidade é de sondas a cada 5 s (resolução limitada); o alarme não aciona sirene física (grava arquivo e publica no MQTT).",
    "<b>Ponto de atenção:</b> o alarme repete a cada 60 s; em produção convém escalonamento e reconhecimento humano (ack) para não gerar fadiga de alarme."]),
 P("10. Ameaças potencializadas por IA e controles (RT-18) — Projetado", "h1"),
 T([["Ameaça no cenário", "Por que é eficaz", "Controle", "Tipo"],
  ["E-mail de phishing gerado por IA (sem erros, personalizado)", "Remove os sinais clássicos (erros de português) e usa contexto da prefeitura", "DMARC quarantine + alinhamento estrito; não confiar na “qualidade do texto”; link verificado; MFA resistente a phishing (WebAuthn) para coordenação", "Técnico"],
  ["Áudio de WhatsApp com voz clonada do secretário", "Autoridade + urgência; voz não é prova de identidade", "Verificação fora de banda (ligar de volta ao número cadastrado); palavra-código combinada pessoalmente; regra de duas pessoas; nenhuma mudança de acesso/bomba só por pedido de voz", "Processo"],
  ["Página falsa coletando credenciais", "Cópia fiel do painel", "Acesso ao painel só via VPN; domínio e certificado conhecidos; TOTP/WebAuthn; alerta de login anômalo", "Técnico"],
  ["Reconhecimento por OSINT para personalizar o golpe", "IA raspa dados públicos de voluntários", "Minimizar dados públicos da associação; treinamento; simulação periódica", "Humano"]], [3.6, 3.6, 7.6, 2.2]),
 P("11. Prompt injection e LLM (RT-17) — Não aplicável", "h1"), P("O protótipo <b>não usa LLM</b>; portanto não há guardrails nem testes de prompt injection a reportar, e o critério C6 não pode contar com esse item. Mapeamento de projeto caso um assistente venha a ser adicionado: OWASP LLM01 (prompt injection direta/indireta), LLM02 (vazamento de dados) e LLM06 (agência excessiva); MITRE ATLAS AML.T0051 e AML.T0057. Regra inegociável: o LLM não aciona atuadores."),
 P("12. Resumo do que falta executar pela equipe", "h1"), *B([*([] if PH else ["Campanha Gophish e preenchimento da tabela da seção 6 (docs/GUIA_GOPHISH.md)."]), *([] if WG else ["Subir o túnel WireGuard (docs/GUIA_WIREGUARD.md)."]), "Exercitar vpn/nftables_edge.conf (regras do nó de borda) com tráfego.", "Subir o Wazuh e validar as regras com wazuh-logtest.", "Medir energia e CPU em hardware real (Raspberry Pi).", "Preencher turma, grupo e o nome do coletor na cadeia de custódia."])]
build(f"{H}/docs/out/GS2026.2_TURMA_GRUPO_E3.pdf", "E3 Relatório de Testes de Segurança", s); print("E3 ok")
