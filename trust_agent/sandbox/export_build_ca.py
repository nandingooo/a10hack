"""Optional: export this Windows machine's existing public trust roots for builds."""
import hashlib
import ssl
from pathlib import Path

if not hasattr(ssl,'enum_certificates'):
    raise SystemExit('Copy your organization public CA .crt files into build-certs/ on this platform.')
directory=Path(__file__).resolve().parents[1]/'build-certs'
directory.mkdir(exist_ok=True)
count=0
for data,encoding,trust in ssl.enum_certificates('ROOT'):
    if encoding=='x509_asn' and (trust is True or '1.3.6.1.5.5.7.3.1' in trust):
        (directory/(hashlib.sha256(data).hexdigest()+'.crt')).write_text(ssl.DER_cert_to_PEM_cert(data),encoding='ascii')
        count+=1
print(f'Exported {count} existing public trust roots to {directory}. TLS verification remains enabled.')
