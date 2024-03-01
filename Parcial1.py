import Crypto.Util.number
import hashlib

m = "x" * 1050
msgBytes = bytes(m , 'utf-8')
hashMsg = hashlib.sha256(msgBytes).hexdigest()
print("El mensaje hasheado es: ", hashMsg)

msg = [m[i:i+128] for i in range(0, len(m), 128)]

bits= 1024
A=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

B=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

print("A:", A)
print("B:", B)

#Obtener los primos para Alice y Bob
pA=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

pB=Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)

print("pA:", pA)
print("pB:", pB)

na=A*B

print("na:", na)

nb=pA*pB

print("nb:", nb)

phiA=(A-1)*(B-1)

print("phiA:", phiA)

phiB=(pA-1)*(pB-1)

print("phiB:", phiB)

#por razones de eficiencia usaremos el numero 4 de fer,at, 65537, debido a que es un primo largo y no es potencia de 2
#y como forma parte de la clave pública no es necesario calcularlo
e=65537

#Caclular la llave privada de alice y bob

dA=Crypto.Util.number.inverse(e, phiA)
print("dA:", dA)

dB=Crypto.Util.number.inverse(e, phiB)
print("dB:", dB)

encrypted_msg = []

for j in msg:
    w = int.from_bytes(str(j).encode('utf-8'), byteorder='big')
    c = pow(w, e, nb)
    print("Mensaje cifrado: ", c, "\n")
    encrypted_msg.append(c)

decrypted_msgs = []

for c in encrypted_msg:
    w = pow(c, dB, nb)
    decrypted_msg_bytes = w.to_bytes((w.bit_length() + 7) // 8, byteorder='big')
    decrypted_msgs.append(decrypted_msg_bytes)

# Juntar todas las oraciones
joined_msg = b''.join(decrypted_msgs).decode('utf-8')

print("Mensaje descifrado y unido: ", joined_msg)







