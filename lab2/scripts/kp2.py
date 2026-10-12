import sys, os, tempfile
from pykeepass import PyKeePass
data = open('out/Hidden.kdbx','rb').read()
base = len(data.rstrip(b'\x00'))
print("file size", len(data), "| size without trailing zeros", base)
padded = data + b'\x00'*64
cands = ['4943ABB39473A6F32C11301F4987E7E0','4943abb39473a6f32c11301f4987e7e0',
         'F4FF64C8BAAC57D22F22EDC681055BA6','f4ff64c8baac57d22f22edc681055ba6']
tmp = tempfile.mktemp(suffix='.kdbx')
for pw in cands:
    for L in range(base-16, base+17):
        open(tmp,'wb').write(padded[:L])
        try:
            kp = PyKeePass(tmp, password=pw)
        except Exception as e:
            m = str(e)
            if 'padded' in m or 'Data must' in m:
                continue
            print(pw, L, '->', type(e).__name__, m[:80])
            continue
        print("OPENED with", pw, "length", L)
        for g in kp.groups: print("GROUP:", g.path)
        for e in kp.entries: print("ENTRY:", e.path, "|", e.username, "|", e.password, "|", e.notes)
        sys.exit()
print("no success")
