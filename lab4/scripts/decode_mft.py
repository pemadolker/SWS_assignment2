import re
text = open('mft.txt').read()
idx = text.find('Important.txt')
chunk = text[idx:idx+3000]
data_start = chunk.find('$DATA')
data_chunk = chunk[data_start:data_start+2000]
hex_bytes = []
for line in data_chunk.split(chr(10)):
    m = re.match(r'^[0-9a-fA-F]{8,10}:\s+((?:[0-9a-fA-F]{2}\s+){1,16})', line)
    if m:
        hex_bytes.extend(m.group(1).split())
    if '***' in line:
        break
raw = bytes(int(b, 16) for b in hex_bytes)
clean = raw.replace(b'\r\n\r\n\r\n', b'').replace(b'\r\n', b'')
print(clean.decode('ascii', errors='replace'))
