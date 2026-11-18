# Guia: campanha de phishing simulado (RT-11) — ~1 h, tudo em lab isolado

**Regras (enunciado, secao 7):** alvos = SOMENTE contas ficticias criadas pela equipe; nunca coletar credenciais reais; nada sai do seu computador; consentimento por escrito de quem for "alvo". Voz clonada: so de integrante que consentir por escrito e sempre identificada como sintetica (pode ser omitida).

## 1. Preparar (Linux/WSL, rede isolada)
```bash
# Mailpit = servidor SMTP de laboratorio com caixa de entrada web (nada sai para a internet)
docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit      # caixa: http://127.0.0.1:8025
# Gophish: baixe a release oficial linux-64bit em github.com/gophish/gophish/releases e extraia
cd gophish && sed -i 's/0.0.0.0:80/127.0.0.1:8080/; s/"listen_url": "0.0.0.0:3333"/"listen_url": "127.0.0.1:3333"/' config.json
./gophish        # anote a senha inicial impressa no console; painel: https://127.0.0.1:3333
```
Sem Docker: use o binario do Mailpit (github.com/axllent/mailpit/releases) ou `python3 -m aiosmtpd -n -l 127.0.0.1:1025`.

## 2. Configurar no painel do Gophish
1. **Sending Profile:** SMTP `127.0.0.1:1025`, sem TLS/usuario; From `Prefeitura Serra Clara <aviso@vilaaurora.example>`.
2. **Users & Groups:** 5 a 10 contas ficticias `nome.fake@vilaaurora.example` (cada integrante controla algumas caixas e age como "voluntario": abre, clica ou reporta conforme o cenario). **Anote isso no relatorio:** as metricas refletem o comportamento da equipe, nao de voluntarios reais.
3. **Landing Page:** clone simples do login do painel; marque **Capture Submitted Data** e **NAO** marque *Capture Passwords*; redirecione para uma pagina "Isto foi um treinamento" (texto da secao 6 do E3).
4. **Email Templates (3 cenarios):**
   - **C1** "Atualizacao obrigatoria de acesso ao painel" (texto bem escrito, personalizado, urgencia moderada).
   - **C2** "Chuva forte: confirme seu acesso ao abrigo" (urgencia da Defesa Civil, link para pagina falsa).
   - **C3** "Pedido urgente do secretario" pedindo liberar acesso a um terceiro (cenario de voz/WhatsApp: use so texto, ou audio sintetico identificado, com consentimento escrito).
   Use `{{.URL}}` no link e marque *Add Tracking Image*.
5. **Campaigns:** crie uma campanha por cenario, URL `http://127.0.0.1:8080`, grupo de teste. Lance cada uma e **aja nas caixas do Mailpit** (http://127.0.0.1:8025): alguns abrem, alguns clicam, alguns enviam dados na pagina falsa, e **reporte** os suspeitos (no Gophish: abra `http://127.0.0.1:8080/report?rid=<RID>` — o RID aparece no link da mensagem — ou use o botao/plugin de reporte).
6. Em cada campanha: **Results → Export CSV → "Raw Events"** e salve como `phishing_C1.csv`, `phishing_C2.csv`, `phishing_C3.csv` na pasta `data_phishing/` do repositorio (essas pastas **nao** devem conter dados reais).

## 3. Calcular as metricas REAIS
```bash
python3 docs/phishing_metrics.py C1 data_phishing/phishing_C1.csv
python3 docs/phishing_metrics.py C2 data_phishing/phishing_C2.csv
python3 docs/phishing_metrics.py C3 data_phishing/phishing_C3.csv
python3 docs/build_e3.py        # a secao 6 do E3 passa a usar esses numeros
```
O script ignora a coluna `details` (pode conter dados enviados) e **nao copia** nenhum valor digitado.

## 4. SPF/DKIM/DMARC na campanha (opcional, melhora o C4)
O Mailpit nao valida dominio. Para medir o efeito do DMARC, envie por um MTA de lab (Postfix + opendkim + opendmarc) com os registros de `mail/dns_records.txt` e um DNS local (dnsmasq). Se nao fizer, **diga no relatorio** que SPF/DMARC nao foram exercitados na campanha (so o DKIM foi verificado, em `tests/dkim_test.py`).
