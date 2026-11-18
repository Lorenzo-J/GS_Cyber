import sys, hashlib, csv, collections, json; sys.path.insert(0, __import__("os").path.dirname(__file__))
from lib import *
coc = list(csv.DictReader(open(f"{H}/evidence/INC-VA-0712-LAB/cadeia_de_custodia.csv"))); tl = list(csv.DictReader(open(f"{H}/forensics/timeline.csv")))
al = [json.loads(l) for l in open(f"{H}/siem/alerts.jsonl")]; audit = [json.loads(l) for l in open(f"{H}/soar/state/audit.jsonl")]
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
ORIG = {"gophish.jsonl": "SINTÉTICO", "vpn.jsonl": "SINTÉTICO", "painel_audit.jsonl": "SINTÉTICO", "mosquitto_trecho.log": "REAL (capturado)", "web_painel_vuln.jsonl": "REAL (capturado)", "alerts.jsonl": "DERIVADO (detecção)", "audit.jsonl": "DERIVADO (SOAR, dry-run)", "timeline.csv": "DERIVADO", "sqli_evidence.txt": "REAL (capturado)"}
for r in coc: r["verif"] = sha(r["copia"]) == r["sha256_na_coleta"]; r["orig"] = next(v for k, v in ORIG.items() if r["arquivo_original"].endswith(k))
nok = sum(r["verif"] for r in coc); hx = lambda h: h[:32] + "<br/>" + h[32:]
s = cover("E4", "Laudo Forense — INC-VA-0712")
s += [P("1. Identificação e escopo", "h1"),
 T([["Campo", "Conteúdo"], ["Caso", "INC-VA-0712-LAB (reprodução em laboratório do incidente INC-VA-0712)"], ["Solicitante", "Associação Rede Comunitária Vila Aurora (cenário fictício)"], ["Analistas", "Lorenzo Costa Jordão (RM 99819); Thiago Carrasco de Souza (RM 99571)"],
   ["Escopo", "Reproduzir a cadeia de ataque do INC-VA-0712 em ambiente isolado, detectá-la, coletar evidências com integridade e consolidar linha do tempo e mapeamento MITRE ATT&CK."], ["Natureza", "Laudo de <b>reprodução controlada</b>. Não investiga um incidente real: não há vítimas, dados pessoais ou sistemas de terceiros."]], [3.5, 13.5]),
 P("<b>Aviso de transparência.</b> Parte dos eventos é <b>sintética</b> (e-mail de phishing, clique, envio de credencial fictícia, login VPN e alteração do agendamento da bomba), pois Gophish e WireGuard não foram executados no ambiente de desenvolvimento e o painel de laboratório não possui função de agendamento. São os registros marcados como SINTÉTICO. São <b>reais (capturados)</b> o ataque de SQL Injection contra o painel vulnerável e as rejeições TLS do broker MQTT.", "warn"),
 P("2. Resumo das conclusões", "h1"),
 *B([f"A cadeia reproduzida seguiu o encadeamento do INC-VA-0712: phishing → credencial → acesso remoto sem MFA → SQL Injection no painel → manipulação do atuador → tentativas de comando ao atuador sem identidade válida.",
    f"O SQL Injection foi <b>comprovadamente explorável</b> na versão vulnerável: extração da tabela de usuários e do esquema do banco (evidência EV-05 e EV-09).",
    f"O motor de detecção gerou {len(al)} alertas, cobrindo as quatro regras do RT-13 (VPN anômala, SQLi, dispositivo sem certificado válido, atuador fora do perfil).",
    f"Das {len(coc)} evidências, {nok} mantiveram o SHA-256 idêntico ao da coleta na reverificação feita na geração deste laudo.",
    "Limite do que se afirma: a reprodução prova que a cadeia é tecnicamente viável e detectável; <b>não</b> prova como o ataque real ocorreu."]),
 P("3. Metodologia e ferramentas", "h1"),
 P("Reprodução: forensics/reproduce_incident.py (alvo somente 127.0.0.1). Detecção: siem/detect.py. Resposta: soar/soar.py. Coleta: forensics/collect_evidence.py (cópia somente leitura, SHA-256 na coleta e reverificação). Linha do tempo: forensics/timeline.py. Todo o código está no repositório (E2). Não foi usado FTK Imager, Autopsy nem plaso; as evidências são arquivos de log (não há imagem de disco). <b>Não houve captura de memória</b> (Volatility não utilizado)."),
 P("4. Evidências e integridade (SHA-256)", "h1"),
 T([["ID", "Arquivo", "Origem", "SHA-256 na coleta", "Bytes", "Reverif."]] + [[r["id"], r["arquivo_original"].split("/")[-1], r["orig"], hx(r["sha256_na_coleta"]), r["bytes"], "OK" if r["verif"] else "ALTERADO"] for r in coc], [1.2, 3.6, 3, 6.4, 1.2, 1.6]),
 P("5. Cadeia de custódia", "h1"),
 T([["ID", "Coletado em (UTC)", "Host / usuário SO", "Método", "Coletor declarado"]] + [[r["id"], r["coletado_em_utc"], f'{r["host"]} / {r["usuario_so"]}', r["metodo"], r["coletor_declarado"]] for r in coc], [1.2, 3.4, 4.2, 5.2, 3]),
 P("O campo <b>coletor declarado</b> precisa ser preenchido pelo integrante que executar a coleta (parâmetro --collector). Sem esse nome, a cadeia de custódia está <b>incompleta</b> quanto a “quem coletou”. As cópias foram gravadas com permissão somente leitura.", "warn"),
 P("Termo de custódia (assinar após a coleta definitiva): Coletor: ________________  Responsável pela guarda: ________________  Data: ____/____/______", "p"),
 PageBreak(), P("6. Linha do tempo consolidada (UTC)", "h1"), P("Relógio único do host de laboratório (sem divergência entre fontes). No incidente original os relógios estavam dessincronizados; <b>a sincronização NTP não foi demonstrada neste ambiente</b> e é requisito para o ambiente real.")]
s.append(T([["Horário (UTC)", "Fonte", "Origem", "Evento", "Detalhe"]] + [[r["ts_utc"][11:], r["fonte"], r["origem"], r["evento"], r["detalhe"][:75]] for r in tl], [2.2, 2.2, 1.9, 3.4, 7.3]))
tec = collections.OrderedDict()
for r in tl:
    for t in r["tecnica"].split(";"): tec.setdefault(t.strip(), set()).add(r["evento"].split(" ")[0])
s += [P("7. Mapeamento MITRE ATT&CK", "h1"),
 T([["Fase", "Técnica", "Evidência / fonte"],
  ["Acesso inicial", "T1566.002 Spearphishing Link", "EV-01 (sintético)"], ["Execução", "T1204.001 User Execution: Malicious Link", "EV-01 (sintético)"],
  ["Acesso a credenciais", "T1598.003 / T1056.003 Captura em portal web", "EV-01 (sintético)"], ["Acesso inicial / Persistência", "T1078 Valid Accounts; T1133 External Remote Services", "EV-04 (sintético) → alerta R-VPN-01"],
  ["Acesso inicial / Coleta", "T1190 Exploit Public-Facing Application; T1213 Data from Information Repositories", "EV-05, EV-09 (reais) → alertas R-SQLI-01/02"],
  ["Impacto ICS", "T0836 Modify Parameter", "EV-03 (sintético) → alerta R-ACT-01"], ["Impacto ICS (tentativa bloqueada)", "T0855 Unauthorized Command Message", "EV-02 (real) → alerta R-DEV-01"]], [4, 7.5, 5.5]),
 P("8. Resposta automatizada e controle humano", "h1"),
 P("Ações de baixo risco executadas automaticamente (modo dry-run para rede/VPN): " + "; ".join(sorted({a["action"] for a in audit if a.get("auto")})) + ". Ação de alto impacto (<b>desligar a bomba</b>) foi apenas <b>enfileirada para aprovação humana</b> e, na demonstração, um perfil sem papel de coordenação teve a aprovação <b>negada</b>. O SOAR recusa bloquear loopback, redes privadas e IPs de gerência."),
 P("9. Análise e lacunas", "h1"),
 *B(["<b>O que se pode afirmar:</b> cada etapa da cadeia gera evidência correlacionável por tempo e IP; a versão corrigida e as regras de detecção interrompem ou alertam em cada elo reproduzido.",
    "<b>O que o incidente original não permitiu afirmar:</b> logs dispersos, relógios dessincronizados e parte sobrescrita impediram determinar o que foi acessado. A nova arquitetura endereça isso com coleta central, NTP, retenção e hash na coleta — porém o NTP e o SIEM Wazuh <b>não foram demonstrados</b> aqui.",
    "<b>Não foi possível</b> reproduzir o agendamento da bomba pelo painel (função inexistente no lab) nem a voz clonada (não gerada, por ética e consentimento).",
    "O MTTD medido (E3) refere-se a logs locais; em produção há latência de rede e do SIEM."]),
 P("10. Recomendações", "h1"),
 *B(["Ativar MFA e retirar a VPN legada; manter apenas WireGuard com acesso administrativo atrás de MFA.", "Manter a versão parametrizada do painel e privilégio mínimo no banco; remover o painel legado.", "Habilitar NTP em todos os nós e enviar logs ao SIEM com retenção mínima de 12 meses.",
    "Exigir aprovação humana para ações de alto impacto no atuador; testar o procedimento em exercício semestral.", "Adotar verificação fora de banda e palavra-código para pedidos urgentes (voz clonada)."]),
 P("11. Limitações", "h1"), P("Reprodução em um único host; eventos de phishing, VPN e agendamento sintéticos; sem captura de memória nem imagem de disco; custódia dependente do preenchimento do coletor; sem Wazuh.")]
build(f"{H}/docs/out/GS2026.2_TURMA_GRUPO_E4.pdf", "E4 Laudo Forense INC-VA-0712", s)
print("E4 ok; integridade:", nok, "/", len(coc))
