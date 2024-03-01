#Fernando Falla 2do Ejercicio
import hashlib
from Crypto.Util.number import getPrime, inverse
import Crypto.Random


def read_last_bytes(file, n_bytes):
    with open(file, "rb") as f:
        f.seek(-n_bytes, 2)
        return f.read(n_bytes)


bits = 1024
pA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
e = 65537
dA = inverse(e, phiA)


with open("NDA.pdf", "rb") as f:
    pdf_bytes = f.read()
    pdf_hash = int.from_bytes(hashlib.sha256(pdf_bytes).digest(), "big")
signature = pow(pdf_hash, dA, nA)
print("Hash Alice: ", pdf_hash)
signature_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder="big")
with open("NDA.pdf", "ab") as f:
    f.write(signature_bytes)

signature_bytes_from_pdf_AC = read_last_bytes("NDA.pdf", 256)
signature_int_from_pdf_AC = int.from_bytes(signature_bytes_from_pdf_AC, byteorder="big")


with open("NDA.pdf", "rb") as f:
    pdf_bytes_AC = f.read()[:-256]
    pdf_hash_AC = int.from_bytes(hashlib.sha256(pdf_bytes_AC).digest(), "big")

print("Hash Ac:", pdf_hash_AC)
# Verificación por AC con la publica de Alice
sig_verif_AC = pow(signature_int_from_pdf_AC, e, nA)
print("Firma verificada por AC:", sig_verif_AC == pdf_hash_AC)


with open("NDA.pdf", "wb") as f:
    f.write(pdf_bytes_AC)

pAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)
eAC = 65537
dAC = inverse(eAC, phiAC)

signature_ac = pow(pdf_hash_AC, dAC, nAC)

signature_ac_bytes = signature_ac.to_bytes(
    (signature_ac.bit_length() + 7) // 8, byteorder="big"
)
with open("NDA.pdf", "ab") as f:
    f.write(signature_ac_bytes)

signature_bytes_from_pdf_BOB = read_last_bytes("NDA.pdf", 256)

signature_int_from_pdf_BOB = int.from_bytes(
    signature_bytes_from_pdf_BOB, byteorder="big"
)

with open("NDA.pdf", "rb") as f:
    pdf_bytes_BOB = f.read()[:-256]
    pdf_hash_BOB = int.from_bytes(hashlib.sha256(pdf_bytes_BOB).digest(), "big")
print("Hash Bob:", pdf_hash_BOB)
pdf_hash_verif_bob = pow(signature_ac, eAC, nAC)
print("Firma verificada por Bob:", pdf_hash_verif_bob == pdf_hash_AC)
