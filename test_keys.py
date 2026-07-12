import base64, struct

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF

def to_uint32_list(data):
    n = len(data) // 4
    return [struct.unpack('<I', data[i*4:(i+1)*4])[0] for i in range(n)]

def from_uint32_list(v):
    return b''.join(struct.pack('<I', x & MASK) for x in v)

def xxtea_decrypt(data, key):
    if len(data) < 8 or len(key) < 4:
        return None
    v = to_uint32_list(data)
    n = len(v)
    if n < 2:
        return None
    k = key[:16].ljust(16, bytes([0]))
    k = to_uint32_list(k)
    y = v[0]
    q = 6 + 52 // n
    sum_val = (DELTA * q) & MASK
    while sum_val != 0:
        e = (sum_val >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum_val ^ y) + (k[(p & 3) ^ e] ^ z)))) & MASK
            y = v[p]
        z0 = v[n - 1]
        v[0] = (v[0] - ((((z0 >> 5) ^ (y << 2)) + ((y >> 3) ^ (z0 << 4))) ^ ((sum_val ^ y) + (k[(0 & 3) ^ e] ^ z0)))) & MASK
        y = v[0]
        sum_val = (sum_val - DELTA) & MASK
    result = from_uint32_list(v)
    pad = result[-1]
    if pad < 4:
        result = result[:-pad]
    return result

# Test with the blackboard.lua file
with open(r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\7304173362844684100_1\code\blackboard.lua', 'rb') as f:
    raw = f.read()

text = raw.decode('utf-8', errors='ignore')
b64 = text[6:].strip()
cipher = base64.b64decode(b64)

keys = [
    b'scHC6MQzMeyHHpKGyJSLFShQtYplQl',
    b'yRIVuhFPufTheN9EdWXhqOZAVhpobd',
    b'b48e6ef44',
    b'b48e6ef44scHC6MQzMeyHHpKG',
    b'b48e6ef44yRIVuhFPufTheN9E',
    b'scHC6MQzMeyHHpKG',
    b'yRIVuhFPufTheN9E',
    b'miniworld',
    b'MiniWorld',
    b'MINIWORLD',
    b'miniuniverse',
    b'RainbowMini',
    b'RainbowMiniMastPc',
]

for k in keys:
    result = xxtea_decrypt(cipher, k)
    if result:
        printable = sum(1 for b in result if 32 <= b <= 126)
        pct = printable * 100 // len(result) if result else 0
        preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result[:80])
        print(f'Key={k}: {len(result)}B printable={pct}% -> {preview}')
    else:
        print(f'Key={k}: failed')
