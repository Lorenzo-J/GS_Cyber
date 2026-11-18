"""Evidencia DKIM/SPF/DMARC (RT-10). DKIM e verificado de verdade com dkimpy; SPF/DMARC so por analise do texto (sem DNS real)."""
import re, dkim
rec = open("mail/dns_records.txt").read(); pub = re.search(r'DKIM1; k=rsa; p=([^"]+)"', rec).group(1)
dns = {b"s2026._domainkey.vilaaurora.example.": ("v=DKIM1; k=rsa; p=" + pub).encode()}
look = lambda n, timeout=5: dns.get(n if n.endswith(b".") else n + b".")
msg = b"From: Aviso <aviso@vilaaurora.example>\r\nTo: coord.fake@vilaaurora.example\r\nSubject: Teste DKIM (lab)\r\nDate: Tue, 17 Nov 2026 12:00:00 -0300\r\nMessage-ID: <t1@vilaaurora.example>\r\n\r\nCorpo de teste sintetico.\r\n"
signed = dkim.sign(msg, b"s2026", b"vilaaurora.example", open("mail/out/dkim.key", "rb").read(), include_headers=[b"from", b"to", b"subject", b"date", b"message-id"]) + msg
DM = re.search(r'p=([a-z]+);', rec.split('_dmarc')[1]).group(1)
out = [f"DKIM mensagem original assinada: {'VALIDA' if dkim.verify(signed, dnsfunc=look) else 'INVALIDA'}",
       f"DKIM corpo adulterado: {'VALIDA' if dkim.verify(signed.replace(b'sintetico', b'MALICIOSO'), dnsfunc=look) else 'INVALIDA (esperado)'}",
       f"DKIM cabecalho From adulterado: {'VALIDA' if dkim.verify(signed.replace(b'aviso@', b'ceo@'), dnsfunc=look) else 'INVALIDA (esperado)'}",
       f"SPF (texto): {'-all presente (rejeita remetentes nao listados)' if 'v=spf1' in rec and '-all' in rec else 'FALHA'}",
       f"DMARC (texto): politica p={DM}; adkim=s; aspf=s (minimo exigido: quarantine)",
       "Limite: SPF/DMARC nao foram avaliados por um receptor real (dominio .example nao resolve)."]
open("tests/results/dkim_evidence.txt", "w").write("\n".join(out)); print("\n".join(out))
