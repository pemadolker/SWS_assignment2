import base64
data = open('vip.txt').read().strip()
step1 = base64.b64decode(data)
step2 = ''.join(chr(b ^ 3) for b in bytearray(step1))
print(step2)
