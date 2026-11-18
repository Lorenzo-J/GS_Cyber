# Guia: WireGuard + segmentacao (RT-06, RT-07)

## A) Segmentacao com trafego (JA TESTADO no repositorio, so precisa de root)
```bash
sudo bash tests/segmentation_test.sh     # gera tests/results/segmentation_evidence.txt
```
Roda 11 conexoes SEM regras (todas passam) e COM `vpn/nftables.conf` (so as permitidas passam). Precisa de iproute2, nftables, python3. Funciona em Linux/WSL2 (nao em containers sem NET_ADMIN).

## B) Tunel WireGuard real (NAO foi possivel testar no ambiente de desenvolvimento: sem modulo de kernel)
```bash
sudo apt install wireguard wireguard-tools iproute2 nftables
bash vpn/gen_wg.sh                       # chaves em vpn/keys (nao versionar)
sudo bash tests/wireguard_netns_test.sh  # sobe hub e borda em namespaces, testa handshake, ping e revogacao do peer
```
Saida: `tests/results/wireguard_evidence.txt` (handshake, ping pelo tunel, ping bloqueado apos remover o peer, e cifras). Anexe esse arquivo e um print do `wg show` ao E3 (secao 4) e atualize o texto para "Testado".

## C) MFA no acesso administrativo
WireGuard nao tem MFA. Escolha UMA opcao e documente: (1) bastion com SSH + TOTP (`libpam-google-authenticator`); (2) ZTNA (Netbird/Firezone) com SSO+MFA; (3) painel admin so no peer `10.200.0.100`, com TOTP (ja implementado no painel). Prefira WebAuthn/FIDO2 para a coordenacao (TOTP e vulneravel a phishing em tempo real).
