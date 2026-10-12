import sys
from pykeepass import PyKeePass
kp = PyKeePass('out/Hidden_clean.kdbx', password=sys.argv[1])
for g in kp.groups: print("GROUP:", g.path)
for e in kp.entries: print("ENTRY:", e.path, "|", e.username, "|", e.password, "|", e.notes)
