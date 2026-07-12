import struct, base64

with open(r'C:\Users\Le Minh\Desktop\Tool\MiniWorldDecoder\key.txt') as f:
    KEY = bytes.fromhex(f.readline().strip().split('#')[0].strip())

def xxtea_decrypt_debug(data, key):
    if not data or len(data) < 8:
        return None
    
    n = len(data) // 4
    v = list(struct.unpack(f'<{n}I', data[:n*4]))
    k = list(struct.unpack('<4I', key))
    
    print(f"  n={n}, data_len={len(data)}, v[0]=0x{v[0]:08X}, v[-1]=0x{v[-1]:08X}")
    
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
    
    plain_len = v[n-1]
    print(f"  After decrypt: v[0]=0x{v[0]:08X}, v[-3]=0x{v[-3]:08X}, v[-2]=0x{v[-2]:08X}, v[-1]=0x{v[-1]:08X}")
    print(f"  plain_len from v[n-1]: {plain_len} (0x{plain_len:X})")
    
    if plain_len > len(data):
        print(f"  ERROR: plain_len ({plain_len}) > data_len ({len(data)})")
        # Try anyway
        payload = struct.pack(f'<{n-1}I', *v[:-1])
        # Try the first plain_len bytes
        if plain_len < len(payload):
            result = payload[:plain_len]
        else:
            result = payload
    else:
        payload = struct.pack(f'<{n-1}I', *v[:-1])
        result = payload[:plain_len]
    
    print(f"  Result length: {len(result)}, first 32 bytes: {result[:32].hex()}")
    return result

# Test on first file
filepath = r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\7304173362844684100_1\code\blackboard.lua'

with open(filepath, 'rb') as f:
    content = f.read()

print(f"File size: {len(content)}")
print(f"Prefix: {content[:6]}")
b64_data = content[6:].decode('ascii')
print(f"Base64 length: {len(b64_data)}")

raw = base64.b64decode(b64_data)
print(f"Raw ciphertext length: {len(raw)}")

result = xxtea_decrypt_debug(raw, KEY)
if result:
    try:
        text = result.decode('utf-8')
        print(f"\nDecrypted OK, {len(text)} chars:")
        print(text[:500])
    except:
        print(f"\nNon UTF-8, trying raw:")
        print(result[:100])
