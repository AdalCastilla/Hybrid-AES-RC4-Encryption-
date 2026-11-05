import copy
#KSA (Key Scheduling Algorithm)
def ksa(key: bytes) -> list[int]:
    if not key:
        raise ValueError("Key must not be empty")


    S = list(range(256))
    j=0
    L=len(key)

    for i in range(256):
        j = (j + S[i] + key[i% L]) % 256
        S[i], S[j] = S[j], S[i]
    return S

#PRGA (Pseudo-Random Generation Algortihm)
def prga(S: list[int], length: int) -> bytes:
    S = S.copy()
    i = 0
    j =0 
    keystream = bytearray()

    for _ in range(length):
        i = (i+1)%256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j])%256
        k = S[t]
        keystream.append(k)
    return bytes(keystream)

#XOR and cipher 
def rc4_encrypt(data: bytes, key:bytes)-> bytes:
    S = ksa(key)

    keystream = prga(S, len(data))

    ciphertext = bytes(
        byte ^ k
        for byte, k in zip(data,keystream)
    )
    return ciphertext

#Decryption 
def rc4_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return rc4_encrypt(ciphertext, key)
