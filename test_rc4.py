
from rc4 import rc4_encrypt, rc4_decrypt

# Vector de prueba conocido de RC4
key = b"Key"
plaintext = b"Plaintext"

ciphertext = rc4_encrypt(plaintext, key)
recovered = rc4_decrypt(ciphertext, key)

print("Original:", plaintext)
print("Cifrado HEX:", ciphertext.hex().upper())
print("Descifrado:", recovered)

expected = "BBF316E8D940AF0AD3"

assert ciphertext.hex().upper() == expected
assert recovered == plaintext

print("Todas las pruebas pasaron correctamente")
