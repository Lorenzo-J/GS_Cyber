# Checklist de entrega (preencher antes de enviar)
- [ ] Renomear PDFs: `GS2026.2_<Turma>_<Grupo>_E1.pdf`, `_E3.pdf`, `_E4.pdf` (hoje `TURMA`/`GRUPO` no nome).
- [ ] Preencher Turma/Grupo na capa (editar `docs/lib.py`, funcao `cover`, e rodar `python3 docs/build_e1.py; build_e3; build_e4`).
- [ ] Recoletar evidencias com seu nome: `python3 forensics/collect_evidence.py --case INC-VA-0712-LAB --collector "SEU NOME" ...` (ver README) e regerar o E4.
- [ ] Executar a campanha Gophish seguindo `docs/GUIA_GOPHISH.md`; rodar `docs/phishing_metrics.py` por cenario; `python3 docs/build_e3.py`.
- [ ] `sudo bash tests/wireguard_netns_test.sh` (docs/GUIA_WIREGUARD.md) e `sudo bash tests/segmentation_test.sh`; subir o Wazuh e validar regras com wazuh-logtest; regerar o E3.
- [ ] Repositorio ja tem `git init` + commit local: `git remote add origin <URL> && git push -u origin main`. Deve estar publico ou com acesso ao professor; conferir que NAO ha chaves (`git ls-files | grep -E "\.key|\.pem|pki/out|vpn/keys|mail/out"` deve ser vazio).
- [ ] Secao "Uso de IA" ja consta no README e no E1 (declarar ferramentas e finalidade).
- [ ] Video (opcional/confirmar com o professor): 5 a 10 min mostrando queda do WAN, SQLi antes/depois, alerta e revogacao.
- [ ] Entregar ate 19/11 23h59 na plataforma da disciplina.
