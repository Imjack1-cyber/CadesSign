/** Short tips about signing and verifying, for the themes' helpers (Paperclip, the iPadOS Tips widget). */
export const SIGNING_TIPS: readonly string[] = [
  'A detached signature lives in its own .p7s file; keep the original next to it. Enveloping puts the document inside the signature.',
  'B-LT signatures stay checkable after the certificate expires, because the proof of validity travels with them.',
  'OCSP asks a server whether a certificate was revoked; a CRL is the whole list of revoked certificates.',
  'Your keystore holds your private key. Keep it somewhere safe, and keep its password somewhere else.',
  'A timestamp proves the signature existed at that moment, even if your certificate is revoked later.',
]
