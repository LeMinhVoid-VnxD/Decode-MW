import struct, base64, glob

# The XXTEA key from getXXTeaKey (16 bytes at RVA 0x715808)
with open(r'C:\Users\Le Minh\Desktop\Tool\MiniWorldDecoder\key.txt') as f:
    KEY = bytes.fromhex(f.readline().strip().split('#')[0].strip())

def xxtea_decrypt(data, key):
    """Proper Cocos2d-x XXTEA decryption"""    
    if not data or len(data) < 8:
        return None
    
    n = len(data) // 4  # number of uint32 words
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
    
    # Last uint32 = original plaintext length
    plain_len = v[n-1]
    if plain_len > len(data):
        return None
    
    # Extract plaintext from first n-1 words
    payload = struct.pack(f'<{n-1}I', *v[:-1])
    return payload[:plain_len]

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
    
    result = xxtea_decrypt(raw, KEY)
    if result:
        try:
            return result.decode('utf-8')
        except:
            return result.decode('utf-8', errors='replace')
    return None

# Test on all blackboard.lua files
files = glob.glob(
    r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\*\code\blackboard.lua',
    recursive=True
)

print(f"Found {len(files)} files\n")

for f in files:
    result = decrypt_file(f)
    if result:
        lines = result.split('\n')
        print(f"{f.split('CustomAI1\\')[1].split('\\')[0]}: {len(result)} bytes")
        for line in lines[:5]:
            print(f"  {line}")
        print()
    else:
        print(f"FAILED: {f}")
