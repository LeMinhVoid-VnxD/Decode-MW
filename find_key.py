#!/usr/bin/env python3
"""Find the XXTEA key for Mini World by testing candidates on known encrypted files."""
import base64, struct, os, re, sys

DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF

def to_uint32(data):
    n = len(data) // 4
    return [struct.unpack('<I', data[i*4:(i+1)*4])[0] for i in range(n)]

def from_uint32(v):
    return b''.join(struct.pack('<I', x & MASK) for x in v)

def xxtea_decrypt(data, key):
    if len(data) < 8 or len(key) < 4:
        return None
    v = to_uint32(data)
    n = len(v)
    if n < 2:
        return None
    k_data = key[:16].ljust(16, b'\x00')
    k = to_uint32(k_data)
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
    result = from_uint32(v)
    pad = result[-1]
    if pad < 4:
        result = result[:-pad]
    return result

def printable_ratio(data):
    if not data:
        return 0
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    return printable * 100 // len(data)

def is_valid_lua(data):
    if not data or len(data) < 4:
        return False
    # Lua bytecode header
    if data[:4] == b'\x1bLua':
        return True
    # Check if mostly readable ASCII
    sample = data[:min(1024, len(data))]
    ratio = printable_ratio(sample)
    return ratio > 60

def extract_cipher_from_file(path):
    """Extract XXTEA ciphertext from a file, handling various formats."""
    with open(path, 'rb') as f:
        raw = f.read()
    
    text = raw.decode('utf-8', errors='ignore')
    
    # Format 1: "a0817i" + base64
    m = re.match(r'^a0817i\s*([A-Za-z0-9+/=]+)\s*$', text)
    if m:
        try:
            return base64.b64decode(m.group(1))
        except:
            pass
    
    # Format 2: "XXTEA" + base64
    if text.startswith('XXTEA'):
        try:
            return base64.b64decode(text[5:].strip())
        except:
            pass
    
    # Format 3: raw binary (no header)
    # Check if it looks like encrypted data
    if len(raw) >= 8 and len(raw) % 4 == 0:
        return raw
    
    return None

# === TEST FILES ===
test_files = [
    r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\7304173362844684100_1\code\blackboard.lua',
    r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\7304173362844684100_1\code\btree.lua',
]

# === KEY CANDIDATES ===
# From DLL strings
keys = [
    # From MiniBaseGame.dll (32-char strings)
    b'scHC6MQzMeyHHpKGyJSLFShQtYplQl',
    b'yRIVuhFPufTheN9EdWXhqOZAVhpobd',
    # First 16 bytes of each
    b'scHC6MQzMeyHHpKG',
    b'yRIVuhFPufTheN9E',
    # From Program.cs
    b'b48e6ef44',
    b'b48e6ef44scHC6MQzMeyHHpKG',
    b'b48e6ef44yRIVuhFPufTheN9E',
    # Common Mini World / Cocos2d-x keys
    b'2dxLua',
    b'MiniWorld',
    b'miniworld',
    b'MINIWORLD',
    b'Mini World',
    b'miniworldgame',
    b'RainbowMini',
    b'RainbowMiniMastPc',
    b'hello-miniworld',
    # From search result - other game keys
    b'kaiqigu-chuangshiji',
    b'kaiqigu-chuangsh',
    # Device IDs / config values
    b'miniuniverse',
    b'MINIW',
]

# Try extracting 16+ byte strings from DLL
print("Scanning DLL for 16+ byte ASCII strings...")
dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libMiniBaseEngine.dll'
with open(dll_path, 'rb') as f:
    dll_data = f.read()

current = b''
for b in dll_data:
    if 32 <= b <= 126:
        current += bytes([b])
    else:
        if len(current) >= 16:
            s = current.decode('latin-1')
            if s not in [k.decode('latin-1') for k in keys]:
                keys.append(current)
        current = b''

print(f"Total key candidates: {len(keys)}")
print()

# Test each key against each file
for fpath in test_files:
    if not os.path.exists(fpath):
        print(f"File not found: {fpath}")
        continue
    print(f"\n{'='*60}")
    print(f"Testing file: {fpath}")
    cipher = extract_cipher_from_file(fpath)
    if cipher is None:
        print(f"  Could not extract ciphertext")
        continue
    print(f"  Ciphertext: {len(cipher)} bytes")
    
    for k in keys:
        try:
            result = xxtea_decrypt(cipher, k)
            if result and is_valid_lua(result):
                preview = result[:100]
                try:
                    text = preview.decode('utf-8', errors='replace')
                except:
                    text = repr(preview)
                print(f"\n  *** KEY FOUND: {k!r} ***")
                print(f"  Decrypted size: {len(result)} bytes")
                print(f"  Preview: {text}")
                # Save the decrypted output
                out_dir = r'C:\Users\Le Minh\Desktop\Tool\pkg_output'
                os.makedirs(out_dir, exist_ok=True)
                out_name = os.path.basename(fpath) + '.decoded'
                out_path = os.path.join(out_dir, out_name)
                with open(out_path, 'wb') as f:
                    f.write(result)
                print(f"  Saved to: {out_path}")
                print()
        except Exception as e:
            pass
