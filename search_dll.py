import os

targets = [b'a0817i', b'XXTEA', b'setXXTEAKeyAndSign', b'setXXTEAKey']
dll_dir = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame'

for f in os.listdir(dll_dir):
    if not (f.endswith('.dll') or f.endswith('.exe')):
        continue
    fp = os.path.join(dll_dir, f)
    with open(fp, 'rb') as fh:
        d = fh.read()
    for t in targets:
        p = d.find(t)
        if p >= 0:
            offset_hex = f'0x{p:x}'
            print(f'{f}: found "{t.decode()}" at {offset_hex}')
            # Print context
            start = max(0, p - 50)
            end = min(len(d), p + 100)
            chunk = d[start:end]
            # Extract strings near it
            cur = b''
            for byte in chunk:
                if 32 <= byte <= 126:
                    cur += bytes([byte])
                else:
                    if len(cur) >= 4:
                        print(f'  context: {cur.decode("latin-1")}')
                    cur = b''
            if len(cur) >= 4:
                print(f'  context: {cur.decode("latin-1")}')
