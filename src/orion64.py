def anahtar_uret(parola):
    key = []
    for i in range(8):
        if i < len(parola):
            key.append(ord(parola[i]) % 256)
        else:
            key.append((i * 17) % 256)
    return key

PERM = [2, 0, 4, 6, 1, 3, 5, 7]

def permute(block):
    return [block[i] for i in PERM]

def subbytes(block):
    return [(x + 5) % 256 for x in block]

def key_schedule(key, r):
    return [(k + r) % 256 for k in key]

def sifrele(duz_metin, anahtar):
    data = [ord(c) for c in duz_metin]

    while len(data) % 8 != 0:
        data.append(0)

    ciphertext = []

    for b in range(0, len(data), 8):
        block = data[b:b+8]

        for r in range(3):  # 3 round
            rk = key_schedule(anahtar, r)

            block = [block[i] ^ rk[i] for i in range(8)]
            block = subbytes(block)
            block = permute(block)

        ciphertext.extend(block)

    return ciphertext

INV_PERM = [1, 4, 0, 5, 2, 6, 3, 7]

def inv_permute(block):
    return [block[i] for i in INV_PERM]

def inv_subbytes(block):
    return [(x - 5) % 256 for x in block]

def desifrele(sifreli_metin, anahtar):
    plaintext = []

    for b in range(0, len(sifreli_metin), 8):
        block = sifreli_metin[b:b+8]

        for r in reversed(range(3)):
            rk = key_schedule(anahtar, r)

            block = inv_permute(block)
            block = inv_subbytes(block)
            block = [block[i] ^ rk[i] for i in range(8)]

        plaintext.extend(block)

    return ''.join(chr(x) for x in plaintext if x != 0)

key = anahtar_uret("kriptoloji")
plain = "MERHABA!"

cipher = sifrele(plain, key)
result = desifrele(cipher, key)

print("Düz Metin:", plain)
print("Şifreli Metin:", cipher)
print("Çözülmüş Metin:", result)

key1 = anahtar_uret("kriptoloji")
key2 = anahtar_uret("kriptolOji")  # tek karakter fark

cipher1 = sifrele("MERHABA!", key1)
cipher2 = sifrele("MERHABA!", key2)

print("Anahtar 1 ile Şifreli:", cipher1)
print("Anahtar 2 ile Şifreli:", cipher2)
