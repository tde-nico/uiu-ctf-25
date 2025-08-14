from Crypto.Cipher import AES

# a=264, b=651, c=570, d=530
a=651
b=264
c=570
d=530

ciphertext = bytes.fromhex("41593455378fed8c3bd344827a193bde7ec2044a3f7a3ca6fb77448e9de55155")
key = f"{a*b*c*d}".zfill(16).encode()
cipher = AES.new(key, AES.MODE_ECB)

print(cipher.decrypt(ciphertext))
