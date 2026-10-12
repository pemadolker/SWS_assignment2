# SWS405 Digital Forensics: Assignment 2 (MemLabs)


## 0. Environment and setup

- Kali Linux VM, Volatility 2.6 (standalone Linux binary) for almost all plugins.
- `apt install volatility` was not available and apt was already in a broken-dependency state on my VM, so I followed the assignment's Option B and cloned Volatility from git (`vol.py`, run with `python2`). That build also needed `pycryptodome` installed through Python 2 pip before `hashdump`-related plugins would load.
- `chromehistory` is not part of Volatility, so I cloned `superponible/volatility-plugins`. The standalone binary ignores `--plugins`, so for that one plugin I used the git version of `vol.py`.
- `steghide` could not be installed with apt (same broken dependencies). I downloaded the `.deb` files with `apt download` and installed them with `dpkg -i --force-depends`.
- Shell shortcut used in the commands below:

```bash
alias vol='$HOME/Desktop/Y4S1/sws/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone'
```

A problem that cost me a lot of time on Labs 1 and 2: the Mega downloads came through corrupted the first time. `7z t` reported `Data Error` and the extracted image was far too small, so Volatility could not find a profile or list processes. The fix was to re-download and only extract when `7z t` said `Everything is Ok`, then check the size of the `.raw` file. This is described in the Lab 2 log, and I now check every archive before extracting it.

---

## Lab 2: A New World

**Flags**

| # | Flag | Where it came from |
|---|------|--------------------|
| 1 | `flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}` | `NEW_TMP` environment variable (Base64) |
| 2 | `flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}` | KeePass database, Recycle Bin entry |
| 3 | `flag{oK_So_Now_St4g3_3_is_DoNE!!}` | Password-protected `Important.zip` from a Mega link in Chrome history |

### Investigation log

**Step 1: Getting a usable image.**
First download: `7z t MemLabs-Lab2.7z` gave `ERROR: Data Error`, and the extracted `MemoryDump_Lab2.raw` was only 4.8 MB. `imageinfo` returned "No suggestion" and `pslist` said "No suitable address space mapping found". My first thought was a wrong profile, but the 4.8 MB size didn't make sense for a memory dump that should be about 1 GB, so I suspected the file instead. I re-downloaded the archive, `7z t` passed, and the extracted file was 1073676288 bytes. MD5 of the image: `ddb337936a75153822baed718851716b`.
![Lab 2: archive extracted with 7z, image is 1073676288 bytes, MD5 shown](lab2/evidence/01_archive_verified.png)
*Lab 2: archive extracted with 7z, image is 1073676288 bytes, MD5 shown*

> TODO: add `lab2/evidence/00_corrupt_first_attempt.png`.

> TODO before submitting: compare that MD5 with the one on the MemLabs Lab 2 README and state here that it matches.

**Step 2: Scoping.**

```bash
vol -f MemoryDump_Lab2.raw imageinfo
vol -f MemoryDump_Lab2.raw --profile=Win7SP1x64 pslist
```

Windows 7 SP1 x64. The processes that stand out are `chrome.exe` (parent PID 2296 with several children), `KeePass.exe` (PID 3008), `notepad.exe` (3260) and `cmd.exe` (2096). `DumpIt.exe` (3844) started at 10:38:43, just before the capture, so it is the tool used to make the dump and not the user's activity.
![Lab 2: pslist, Chrome and KeePass running, DumpIt at the end](lab2/evidence/02_pslist.png)
*Lab 2: pslist, Chrome and KeePass running, DumpIt at the end*

**Step 3: Environment variables (Flag 1).**
The assignment says to check `envars` early, so I ran it and looked for anything that doesn't belong in a normal Windows environment.

```bash
vol -f MemoryDump_Lab2.raw --profile=Win7SP1x64 envars | grep NEW_TMP | head -1
echo -n 'ZmxhZ3t3M2xjMG0zX1QwXyRUNGczXyFfT2ZfTDRCXzJ9' | base64 -d; echo
```

`NEW_TMP` appears in every process, with a value of `C:\Windows\` followed by a long string. That is not a real Windows variable, and a temp path wouldn't normally end in random letters and digits. The string uses only Base64 characters and starts with `Zmxh`, which is what `flag` looks like in Base64. Decoding gives Flag 1.
![Lab 2, Flag 1: NEW_TMP environment variable and its Base64 decode](lab2/evidence/03_envars_flag1.png)
*Lab 2, Flag 1: NEW_TMP environment variable and its Base64 decode*

**Step 4: Finding the KeePass database.**

```bash
vol -f MemoryDump_Lab2.raw --profile=Win7SP1x64 filescan > filescan.txt
grep -iE "kdbx|\.rar|\.zip" filescan.txt
vol -f MemoryDump_Lab2.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D ./out
file out/*
```

Found `\Users\SmartNet\Secrets\Hidden.kdbx` at `0x3fb112a0`. `dumpfiles` produced a 4096-byte file and `file` identified it as "Keepass password database 2.x KDBX".
![Lab 2: Hidden.kdbx found with filescan and extracted with dumpfiles](lab2/evidence/04_filescan_dumpfiles_kdbx.png)
*Lab 2: Hidden.kdbx found with filescan and extracted with dumpfiles*

**Step 5: First attempt at the master password (failed).**
The checklist says `hashdump` for credentials, and in Lab 1 an NTLM hash had been the archive password, so I tried that idea first.

```bash
vol -f MemoryDump_Lab2.raw --profile=Win7SP1x64 hashdump
```

I tried the NTLM hashes of SmartNet and Alissa Simpson (upper and lower case) with a small `pykeepass` script. All four runs crashed with `ValueError: Data must be padded to 16 byte boundary in CBC mode`. A wrong password would have given a credentials error instead, so this meant the file itself was damaged and I hadn't tested any password yet. `dumpfiles` writes whole 4 KB pages, so the real database is probably shorter than 4096 bytes with zero padding after it. I stripped the trailing zeros (the real size was **3422 bytes**) and re-ran the test in `kp2.py`. This time the file parsed and all four hashes returned `CredentialsError: Invalid credentials`. So the database was fine and the password simply wasn't one of the hashes.
![Lab 2: hashdump output, candidates for the KeePass master password](lab2/evidence/05_hashdump.png)
*Lab 2: hashdump output, candidates for the KeePass master password*

![Lab 2: database trimmed to 3422 bytes, all four NTLM hashes rejected](lab2/evidence/06_kp2_credentials_error.png)
*Lab 2: database trimmed to 3422 bytes, all four NTLM hashes rejected*

**Step 6: Looking for the real password (dead ends first).**
The assignment says the password won't be next to the file and points to another artifact from the checklist. I checked, in this order:

- `cmdscan` and `consoles`: only a decoy line typed into `cmd.exe`, "Nothing here kids :)".
- `clipboard`: empty.
- `memdump -p 3260` (notepad) and `strings`: only Windows manifest text, plus the window title "Hidden.kdbx - KeePass".
- `grep -iE "\.txt|pass|secret|note" filescan.txt`: this one gave `\Users\Alissa Simpson\Pictures\Password.png` at `0x3fce1c70`.

A file named Password.png in the user's Pictures folder seemed worth checking, so I dumped it. `file` said PNG image data, 1587 x 2245. The big text on the image says the flag is not here, but there is tiny print in the bottom right corner: "Psst!! password is P4SSw0rd_123".
![Lab 2: Password.png recovered from memory, tiny print gives the master password](lab2/evidence/07_password_png.png)
*Lab 2: Password.png recovered from memory, tiny print gives the master password*

**Step 7: Opening the database (Flag 2).**

```bash
head -c 3422 out/Hidden.kdbx > out/Hidden_clean.kdbx
python3 kp3.py 'P4SSw0rd_123'
```

It opened on the first try. Several entries in the "General" group are decoys ("fake", "oh not again!", and so on). The Recycle Bin group has an entry called "Sabka Baap" with username `Flag` and the second flag as its password. This matches the assignment's hint about the "Recycle Bin" entry.
![Lab 2, Flag 2: KeePass opened, flag in the Recycle Bin](lab2/evidence/08_kp3_recycle_bin_flag2.png)
*Lab 2, Flag 2: KeePass opened, flag in the Recycle Bin*

**Step 8: Chrome history (for Flag 3).**

```bash
vol --plugins=$HOME/Desktop/Y4S1/sws/volatility-plugins -f MemoryDump_Lab2.raw --profile=Win7SP1x64 chromehistory
```

With the standalone binary this printed `ERROR: You must specify something to do (try -h)`, meaning it never loaded the plugin. I switched to the git copy of Volatility (`python2 vol.py --plugins=... chromehistory`), redirected the output to `chrome.txt`, and grepped it. The history contains a Mega folder link: `https://mega.nz/#F!TrgSQQTS!H0ZrUzF0B-ZKNM3y9E76lg`. To double-check the plugin output I also ran `strings -a MemoryDump_Lab2.raw | grep mega.nz`, which found the same URL.
> TODO: add `lab2/evidence/09_chromehistory_standalone_fails.png`.

> TODO: add `lab2/evidence/10_chromehistory_mega_link.png`.

> TODO: take `10_chromehistory_mega_link.png` from the git-version run (`grep -iE "mega|drive|dropbox" chrome.txt`).

**Step 9: The password-protected archive (Flag 3).**
The Mega folder (`MemLabs_Lab2_Stage3`) contains `Important.zip`. Its archive comment tells you how to build the password:

```bash
unzip -z Important.zip
# Password is SHA1(stage-3-FLAG) from Lab-1. Password is in lowercase.
```

"Stage 3" of Lab 1 is the flag inside `flag3.png` from the `Important.rar` in Lab 1: `flag{w3ll_3rd_stage_was_easy}` (it literally says "3rd stage" in the picture). I calculated:

```bash
echo -n 'flag{w3ll_3rd_stage_was_easy}' | sha1sum | cut -d' ' -f1
# 6045dd90029719a039fd2d2ebcca718439dd100a
```

I used `-n` so no newline is hashed, and single quotes because the flag contains `{`, `}` and `!`. For comparison I also hashed the Lab 1 stage-1 flag (`b593ac90...`), but the comment names stage 3, so that wasn't used.
Plain `unzip -P` failed with `unsupported compression method 99`. Method 99 means AES encryption, which the standard `unzip` doesn't support. `7z` does:

```bash
7z x Important.zip -p"$(echo -n 'flag{w3ll_3rd_stage_was_easy}' | sha1sum | cut -d' ' -f1)"
```

It reported `Everything is Ok` and extracted `Important.png`, which contains Flag 3.
![Lab 2: zip comment gives the password rule, SHA1 of the Lab 1 stage-3 flag](lab2/evidence/11_zip_comment_and_sha1.png)
*Lab 2: zip comment gives the password rule, SHA1 of the Lab 1 stage-3 flag*

![Lab 2: Important.zip extracted with 7z using the SHA1 password](lab2/evidence/12_7z_extract_stage3.png)
*Lab 2: Important.zip extracted with 7z using the SHA1 password*

![Lab 2, Flag 3: Important.png](lab2/evidence/13_flag3_important_png.png)
*Lab 2, Flag 3: Important.png*

### How I derived the final archive password

The password was never in the Lab 2 memory image. The zip comment said to take the SHA1 of the stage-3 flag from Lab 1, in lowercase. The Lab 1 stage-3 flag is `flag{w3ll_3rd_stage_was_easy}`. I hashed that exact string (without a trailing newline) using SHA1 and used the 40-character lowercase hex digest `6045dd90029719a039fd2d2ebcca718439dd100a` as the password. The archive then needed `7z` rather than `unzip` because of its AES encryption.

### Forensic reasoning

`envars` reads each process's environment block from its memory, so a variable that every process inherited, like `NEW_TMP`, stands out and shows it was set system-wide. Base64 hid the message, but its shape (a long run of alphanumerics starting with `Zmxh`) gave it away. For the database, `filescan` found the file object and `dumpfiles` rebuilt it from cached pages, but the rebuilt copy was padded to a page boundary, which is why I had to trim it to 3422 bytes before it parsed. The master password was never stored next to it. The real password turned up in a second file in the same user's profile, which shows why you check files around the target and not only the target itself. The `hashdump` guess failed, and I kept it in the log because it shows how I narrowed the problem down: the padding error came first, then the credentials error, which told me the file was fine and the password was wrong. `chromehistory` recovers Chrome's history from process memory but needs a community plugin, which is why the standalone build couldn't run it. The last step is evidence correlation across two separate memory images: the Lab 2 archive could only be opened with something found in Lab 1.

---

## Lab 3: The Evil's Den

**Flag (one flag, in two halves)**

`inctf{0n3_h4lf_1s_n0t_3n0ugh}`

- First half: `inctf{0n3_h4lf` (recovered by reversing the script's output)
- Second half: `_1s_n0t_3n0ugh}` (extracted with steghide from the JPEG)

### Investigation log

**Step 1: Getting and checking the image.**
Archive checked with `7z t` before extraction. The image is 1048510464 bytes, MD5 `ce4e7adc4efbf719888d2c87256d1da3`.
> TODO: add `lab3/evidence/01_archive_verified.png`.

> TODO: confirm that MD5 against the Lab 3 README and say so here.

**Step 2: Profile (first attempts failed).**
Since Labs 1 and 2 were `Win7SP1x64`, I assumed the same here and tried `pslist`, `cmdscan` and `consoles` with that profile. They all failed with "No suitable address space mapping found" and "No valid DTB found". `imageinfo` actually suggested `Win7SP1x86_23418, Win7SP0x86, Win7SP1x86_24000, Win7SP1x86`, so this is a 32-bit Windows 7 image. From then on I used `--profile=Win7SP1x86_23418`. Lesson: read `imageinfo` for each image instead of copying the last profile.
> TODO: add `lab3/evidence/02_imageinfo_x86_profile.png`.

**Step 3: Finding the script and its output.**
The first `filescan | grep` for `.py` and `.txt` was swamped by the Python 2.7 installation (`\Python27\Lib\...`), so I filtered on the user's Desktop instead:

```bash
grep -iE "Users.hello.Desktop" filescan.txt
```

This showed three interesting files on `\Users\hello\Desktop\`:

- `evilscript.py.py` at `0x3de1b5f0`
- `vip.txt` at `0x3e727e50`
- `suspision1.jpeg` at `0x04f34148` (the odd, misspelled name, and the only image among the Desktop files)

![Lab 3: script, output file and the oddly named image on the user's Desktop](lab3/evidence/03_filescan_desktop.png)
*Lab 3: script, output file and the oddly named image on the user's Desktop*

**Step 4: Dumping the files.**

```bash
vol -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D ./out
vol -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003e727e50 -D ./out
vol -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x0000000004f34148 -D ./out
file out/*
```

The dumped files have generic names, so I used `file` to tell them apart: the Python script (4096 bytes), the ASCII text (4096) and the JPEG (12288 bytes, 256x197). I renamed them to `evilscript.py`, `vip.txt` and `suspision1.jpeg`. The page padding adds zero bytes, so I viewed the text files with `tr -d '\000'`.
![Lab 3: files dumped, script source and vip.txt](lab3/evidence/04_dumpfiles_script_and_vip.png)
*Lab 3: files dumped, script source and vip.txt*

**Step 5: Reading the script.**
I read the script before doing anything else instead of running it. It does two things to its command-line argument, in this order:

```python
def xor(s):
    return ''.join(chr(ord(i)^3) for i in s)   # XOR every character with 3

def encoder(x):
    return x.encode("base64")                   # Base64 encode the result

arr = encoder(xor(arr))
f.write(arr)                                    # writes to vip.txt
```

So `vip.txt` = Base64(XOR3(plaintext)). Its content is `am1gd2V4M20wXGs3b2U=`.

**Step 6: Reversing it.**
To undo it I have to reverse the order: first Base64-decode, then XOR with 3 again. XOR with the same key twice returns the original value, so the key doesn't change. My own script:

```python
import base64
data = open('vip.txt').read().strip()
step1 = base64.b64decode(data)
step2 = ''.join(chr(b ^ 3) for b in bytearray(step1))
print(step2)
```

Output: `inctf{0n3_h4lf`. That's the first half, and the closing brace is missing, which fits the "two halves" description.
![Lab 3: reverse.py output, first half of the flag](lab3/evidence/05_reverse_py_first_half.png)
*Lab 3: reverse.py output, first half of the flag*

**Step 7: Steganography.**
The task says steganography is involved and the second half needs the first half. I used the first half as the steghide passphrase on the JPEG:

```bash
steghide extract -sf suspision1.jpeg -p 'inctf{0n3_h4lf'
```

It extracted a text file containing `_1s_n0t_3n0ugh}`. Joined with the first half:
`inctf{0n3_h4lf_1s_n0t_3n0ugh}`
> TODO: add `lab3/evidence/06_steghide_extract.png`.

![Lab 3: extracted file with the second half of the flag](lab3/evidence/07_secret_text_second_half.png)
*Lab 3: extracted file with the second half of the flag*

> TODO: add `06_steghide_extract.png` with the command and the full joined flag visible.

### Explanation of the script and how I reversed it

The "malicious" script takes a string, XORs each character's code with the constant 3, Base64-encodes the whole result and writes it to `vip.txt`. Because XOR with the same key undoes itself (`(A ^ 3) ^ 3 = A`), I did not need to find any key. I only had to undo the steps in reverse order: Base64 decode first (since Base64 was applied last), then XOR with 3 on each byte. The output was the first half of the flag. That half doubled as the steghide passphrase, so the two halves depend on each other.

### Forensic reasoning

`filescan` lists file objects that exist in memory even if the files are not open, which is how a script and its output on the user's Desktop could be found with no process pointing to them. `dumpfiles` recovers those files from the cached pages, but the copies are padded to page size, so I looked at them with the zero bytes removed. Reading the script first showed what the transformation was, and then it was just arithmetic. The steganography half shows that evidence in one artifact (the decoded text) can be the key to another (the hidden payload in the image), so the investigation depends on correlating findings. The wrong-profile mistake at the beginning also taught me that the profile has to be checked for every image, because Labs 1 and 2 were 64-bit and Lab 3 is 32-bit.

---

## Lab 4: Obsession

**Flag**

`inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}`

### Investigation log

**Step 1: Scoping.**
`imageinfo` suggested `Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418`. These are close variants of the same kernel. I ran `pslist` with `Win2008R2SP1x64` and it listed processes correctly, so I stayed with it (the first suggestion would have worked too). The image was taken on 2019-06-29. Notable processes: `explorer.exe` for two sessions, `StikyNot.exe` (Sticky Notes, PID 2432), and `DumpIt.exe` (PID 2624, started at 07:29:25, which is the capture tool and not user activity). `StikyNot.exe` fits an "important note" story, but I didn't need it.
![Lab 4: imageinfo and pslist](lab4/evidence/01_imageinfo_pslist.png)
*Lab 4: imageinfo and pslist*

**Step 2: Files on the Desktops.**

```bash
vol -f MemoryDump_Lab4.raw --profile=Win2008R2SP1x64 filescan > filescan.txt
grep -i "Desktop" filescan.txt | grep -viE "desktop.ini|\.lnk"
```

Two users have files on their Desktops:

- `\Users\eminem\Desktop\galf.jpeg` at `0x3e8ad250` and `Screenshot1.png` at `0x3e8d19e0`
- `\Users\SlimShady\Desktop\Important.txt` at `0x3fc398d0`

The images look like the "suspicious" files the task describes, and `Important.txt` is the important text file.
![Lab 4: images and Important.txt on the user Desktops](lab4/evidence/02_filescan_desktop.png)
*Lab 4: images and Important.txt on the user Desktops*

**Step 3: The images first (expected dead end).**
I dumped both images with `dumpfiles`, renamed them (`galf.jpeg`, `Screenshot1.png`) and opened them. `galf.jpeg` is a picture of the Joker and `Screenshot1.png` is a GNOME screenshot. I ran `exiftool` and `strings` on them, and checked them with a signature scan for embedded files. The only anomaly was a warning on `Screenshot1.png`: `[minor] Trailer data after PNG IEND chunk [x301]`, meaning 301 bytes after the end of the PNG. I carved those trailing bytes and looked at them.

> TODO: write one or two sentences on what the trailer bytes (`trailer.bin`, `jpeg_trailer.bin`) and `LMAO.txt` actually contained, and say that there was no flag in them.

Conclusion: the images were a distraction. I kept this in the log because the assignment says a documented dead end still counts as an investigative step, and because I'd rather rule the images out than assume.
![Lab 4: exiftool and strings on the images](lab4/evidence/03_stego_exiftool_strings.png)
*Lab 4: exiftool and strings on the images*

![Lab 4: galf.jpeg opened, a distractor](lab4/evidence/03b_galf_jpeg_opened.png)
*Lab 4: galf.jpeg opened, a distractor*

**Step 4: `dumpfiles` on `Important.txt`.**

```bash
vol -f MemoryDump_Lab4.raw --profile=Win2008R2SP1x64 dumpfiles -Q 0x000000003fc398d0 -D ./out
```

> TODO: add `04_dumpfiles_important_txt_fails.png` and say what happened (no file produced, or an empty/unusable file).

`filescan` still shows the file object, but I did not get the contents back this way, so I went to the MFT.

**Step 5: `mftparser`.**

```bash
vol -f MemoryDump_Lab4.raw --profile=Win2008R2SP1x64 mftparser > mft.txt
grep -i -B3 -A25 "Important.txt" mft.txt
```

The output has an MFT record for `Users\SlimShady\Desktop\Important.txt` (created 2019-06-27 13:14:13, record number 26336, found at offset `0x3bddf000`). The `$DATA` attribute is shown as a hex dump, so the file content sits inside the MFT record. The text is broken into short pieces separated by runs of `0d 0a` (CRLF) bytes, for example `i`, `n`, `ct`, `f{1`, `_is`, `_n0t`, and so on, ending with "Good work :P". I think the blank lines were put in on purpose to make the flag harder to read in a hex dump.
> TODO: add `lab4/evidence/05_mftparser_important_txt.png`.

**Step 6: Putting the pieces back together.**
Instead of joining the fragments by eye, I wrote a short Python script that reads the hex bytes of the `$DATA` block from `mft.txt`, removes the `\r\n` runs and decodes the result:

```python
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
raw = bytes(int(b,16) for b in hex_bytes)
clean = raw.replace(b'\r\n\r\n\r\n', b'').replace(b'\r\n', b'')
print(clean.decode('ascii', errors='replace'))
```

Output: `inctf{1_is_n0t_EQu4l_7o_2_bUt_th1s_d0s3nt_m4ke_s3ns3}Good work :P`. The flag is the part before "Good work :P".
![Lab 4: script rebuilds the flag from the MFT hex dump](lab4/evidence/06_decode_script_flag.png)
*Lab 4: script rebuilds the flag from the MFT hex dump*

### Why `dumpfiles` failed and `mftparser` worked

`filescan` finds file objects in kernel memory, but `dumpfiles` can only rebuild a file from data pages that are actually cached in RAM. A file that is deleted, or whose pages were never loaded, shows up in the listing and still can't be extracted. In NTFS, a very small file is stored directly inside its MFT record as a resident `$DATA` attribute, and the MFT is cached in memory. `mftparser` reads those records directly, so it doesn't need the file's own pages. `Important.txt` is only about 150 bytes, which is small enough to be resident. That is why the same file was unreachable with one plugin and fully readable with the other.

---

## Lab 5: Black Tuesday

**Flags**

| # | Flag | Where it came from |
|---|------|--------------------|
| 1 | `flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}` | Long Base64 `.bmp` filename in IE history (also the archive password) |
| 2 | `flag{W1th_th1s_$taGe_2_1s_c0mPL3T3_!!}` | `Stage2.png` inside the password-protected RAR |

### Investigation log

**Step 1: Scoping.**
`imageinfo` suggested `Win7SP1x64` first (image date 2019-12-20), so I used that profile. The assignment says an archive manager was in use, and WinRAR is the one to find.

> TODO: add `01_archive_verified.png` (`md5sum` and `7z t` for the Lab 5 download) and `02_imageinfo_pslist.png`, and name the WinRAR process and its PID from `pslist.txt`.

**Step 2: The archive.**

```bash
grep -i "\.rar" filescan.txt
```

One result: `\Users\SmartNet\Documents\SW1wb3J0YW50.rar` at `0x3eed56f0`. The file name is odd, so I decoded it: `echo -n 'SW1wb3J0YW50' | base64 -d` gives `Important`. The archive's name is just the Base64 form of "Important". I dumped it with `dumpfiles -Q 0x000000003eed56f0 -D ./out`, which produced a 77824-byte file that `file` identified as "RAR archive data, v5". I renamed it to `Important.rar`. `unrar x` immediately asked for a password for `Stage2.png`. I didn't try to guess or brute-force it, as the assignment tells us not to.
![Lab 5: RAR found with filescan, dumped, and both passwords tried](lab5/evidence/03_filescan_rar_dumpfiles.png)
*Lab 5: RAR found with filescan, dumped, and both passwords tried*

![Lab 5: archive is password protected](lab5/evidence/04_unrar_asks_password.png)
*Lab 5: archive is password protected*

**Step 3: Browser history (first attempt failed).**
Nothing in the process list was suspicious on its own, so I looked at browser history. This machine doesn't use Chrome, so the community plugin from Lab 2 is not the right one. I ran the built-in `iehistory` plugin. The first run wrote only `ERROR: Invalid profile selected` into `ie.txt`, because I had opened a new terminal and the `PROF` variable was empty there. After `export PROF=Win7SP1x64` it worked and produced 479 lines.
> TODO: add `lab5/evidence/05_iehistory_invalid_profile.png`.

**Step 4: Finding the odd filename.**
I sorted the `Location:` lines by length to bring the unusual ones to the top:

```bash
grep -iE "Location:" ie.txt | awk '{print length($0), $0}' | sort -rn | head -15
```

Most of the longest lines are Google redirect URLs and Firefox download pages visited by SmartNet. That fits a user who opened IE to download another browser. The interesting lines are `file:///` entries visited by Alissa Simpson with very long names ending in `.bmp`, in `C:\Users\Alissa Simpson\Pictures\` and `C:\Windows\AppPatch\`. There are two variants of the name that differ in a single character group:

```
ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfNV9EMG4zXyEhfQ
ZmxhZ3shIV93M0xMX2QwbjNfU3Q0ZzMtMV8wZl9MNEJfM19EMG4zXyEhfQ
```

Both start with `Zmxh`, which is `flag` in Base64, so I decoded them:

```
flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}
flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_3_D0n3_!!}
```

The version ending `L4B_5` appears several times, in both folders. The `L4B_3` version appears once. Since this is Lab 5, I guessed the `5` version was the real one, and I treated the other as a decoy and tested both.
![Lab 5: iehistory lines sorted by length, encoded .bmp names](lab5/evidence/06_iehistory_long_filenames.png)
*Lab 5: iehistory lines sorted by length, encoded .bmp names*

![Lab 5: both Base64 filenames decoded](lab5/evidence/07_base64_decode_both.png)
*Lab 5: both Base64 filenames decoded*

**Step 5: Opening the archive.**

```bash
unrar x -p'flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_5_D0n3_!!}' Important.rar
unrar x -p'flag{!!_w3LL_d0n3_St4g3-1_0f_L4B_3_D0n3_!!}' Important.rar
```

The first (`L4B_5`) extracted `Stage2.png` with "All OK". The second gave "Incorrect password for Stage2.png". I used single quotes because the passwords contain `!`, `{` and `}`. `Stage2.png` shows the second flag.
![Lab 5: the L4B_5 string opens the archive, the L4B_3 one is rejected](lab5/evidence/08_unrar_both_passwords.png)
*Lab 5: the L4B_5 string opens the archive, the L4B_3 one is rejected*

![Lab 5, Flag 2: Stage2.png](lab5/evidence/09_stage2_flag.png)
*Lab 5, Flag 2: Stage2.png*

### Browser history plugin

I used `iehistory`, the built-in Volatility plugin for Internet Explorer, because this machine's user was browsing with Internet Explorer (the history shows searches for Chrome and Firefox downloads, which is typical for an IE-only user). IE keeps history in `index.dat` structures that this plugin parses, while Lab 2 was Chrome and needed the community `chromehistory` plugin.

### Forensic reasoning

The archive was found with `filescan` and recovered with `dumpfiles`, but nothing in memory told me its password. The password came from a different artifact: the browser history, where the user had opened files whose names were Base64-encoded flags. That is a good example of why the checklist asks for several kinds of evidence. `hashdump` wasn't needed here because the credential wasn't a Windows account password. The two near-identical filenames were a good reminder to test candidates before trusting one: one decoded string opened the archive and the other was rejected. The decoy also fits the lab number, since the real one says `L4B_5`.

---

## Lab 1

To be added in a later commit.