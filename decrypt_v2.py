import struct, base64, glob, os

with open(r'C:\Users\Le Minh\Desktop\Tool\MiniWorldDecoder\key.txt') as f:
    key_hex = ''
    for line in f:
        line = line.split('#')[0].strip()
        if line:
            key_hex = line
            break
KEY = bytes.fromhex(key_hex)

def xxtea_decrypt_v2(data, key):
    """XXTEA decrypt with custom format: first 4 bytes = big-endian length"""
    if len(data) < 8:
        return None
    
    n = len(data) // 4
    if n < 2:
        return None
    
    v = list(struct.unpack(f'<{n}I', data[:n*4]))
    k = list(struct.unpack('<4I', key))
    
    z, y = v[n-1], v[0]
    q = 6 + 52 // n
    delta = 0x9E3779B9
    sum_val = (q * delta) & 0xFFFFFFFF
    
    while sum_val != 0:
        e = (sum_val >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p-1]
            v[p] = (v[p] - (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum_val ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xFFFFFFFF
            y = v[p]
        z = v[n-1]
        v[0] = (v[0] - (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum_val ^ y) + (k[(0 & 3) ^ e] ^ z)))) & 0xFFFFFFFF
        y = v[0]
        sum_val = (sum_val - delta) & 0xFFFFFFFF
    
    payload = struct.pack(f'<{n}I', *v)
    
    # First 4 bytes = big-endian length
    plain_len = struct.unpack('>I', payload[:4])[0]
    
    if plain_len > len(payload) or plain_len <= 0:
        return None
    
    return payload[4:4+plain_len]

def decrypt_file(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()
    if content[:6] != b'a0817i':
        return None
    b64_data = content[6:].decode('ascii')
    try:
        raw = base64.b64decode(b64_data)
    except:
        return None
    result = xxtea_decrypt_v2(raw, KEY)
    if result:
        return result.decode('utf-8', errors='replace')
    return None

# Test all files
files = glob.glob(
    r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\*\code\blackboard.lua',
    recursive=True
)

print(f"Found {len(files)} files\n")
success = 0
for f in files:
    result = decrypt_file(f)
    if result:
        success += 1
        dirname = os.path.basename(os.path.dirname(os.path.dirname(f)))
        lines = result.split('\n')
        print(f"OK {dirname}: {len(result)} bytes")
        for line in lines[:8]:
            print(f"  {line}")
        print()
    else:
        print(f"FAIL: {f}")

print(f"\n{success}/{len(files)} decrypted successfully")

# Save one decrypted file as example
if success > 0:
    f = files[0]
    result = decrypt_file(f)
    outpath = r'C:\Users\Le Minh\Desktop\Tool\decrypted_example.lua'
    with open(outpath, 'w', encoding='utf-8') as out:
        out.write(result)
    print(f"\nSaved example to {outpath}")
