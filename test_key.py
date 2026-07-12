import struct, base64

# Read candidate key from libMiniBaseEngine.dll
dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libMiniBaseEngine.dll'
with open(dll_path, 'rb') as f:
    dll = f.read()

# The key pointer is at file offset 0x714008
# Let me extract 16 bytes from there as potential XXTEA key
key_bytes = dll[0x714008:0x714008+16]
print(f"Candidate key bytes: {key_bytes.hex()}")

# XXTEA implementation in Python
def xxtea_decrypt(key, data):
    """Standard XXTEA decryption"""
    if not data or len(data) < 4:
        return None
    
    # Treat data as array of 32-bit unsigned integers (little-endian)
    n = len(data) // 4
    if n < 2:
        return None
    
    v = list(struct.unpack(f'<{n}I', data))
    k = list(struct.unpack('<4I', key))
    
    n -= 1
    z = v[n]
    y = v[0]
    q = 6 + 52 // (n + 1)
    sum = (q * 0x9E3779B9) & 0xFFFFFFFF
    delta = 0x9E3779B9
    
    while sum != 0:
        e = (sum >> 2) & 3
        for p in range(n, -1, -1):
            z = v[p-1] if p > 0 else v[n]
            v[p] = (v[p] - (((z>>5 ^ y<<2) + (y>>3 ^ z<<4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))) & 0xFFFFFFFF
            y = v[p]
            if p == 0:
                break
        sum = (sum - delta) & 0xFFFFFFFF
    
    # Pack back
    result = struct.pack(f'<{n+1}I', *v)
    return result

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        content = f.read()
    
    prefix = content[:6]
    assert prefix == b'a0817i', f"Bad prefix: {prefix}"
    
    b64_data = content[6:].decode('ascii')
    try:
        raw = base64.b64decode(b64_data)
    except:
        print(f"  Base64 decode failed")
        return None
    
    result = xxtea_decrypt(key, raw)
    
    # XXTEA can have padding - try to strip null bytes at end
    if result:
        result = result.rstrip(b'\x00')
    
    return result

# Get a test file
import glob
test_files = glob.glob(
    r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\*\code\blackboard.lua',
    recursive=True
)

for test_file in test_files[:3]:
    print(f"\n=== {test_file} ===")
    
    # Try the candidate key directly (16 bytes)
    key = key_bytes
    print(f"Trying key: {key.hex()}")
    result = decrypt_file(test_file, key)
    if result:
        print(f"Decrypted length: {len(result)} bytes")
        try:
            text = result.decode('utf-8')
            print(f"First 200 chars: {text[:200]}")
            if text.isprintable() or any(32 <= ord(c) <= 126 or c in '\n\r\t' for c in text[:50]):
                print("SUCCESS! Looks like valid Lua!")
            else:
                print(f"Not printable: {result[:64].hex()}")
        except:
            print(f"UTF-8 decode failed, raw hex: {result[:64].hex()}")
    else:
        print("Failed to decrypt")
    
    # Try other key formats
    # Try reversed bytes
    key_rev = key[::-1]
    print(f"Trying key reversed: {key_rev.hex()}")
    result = decrypt_file(test_file, key_rev)
    if result:
        print(f"  Result: {result[:100]}")
    
    # Try treating key as array of 4 uint32s (big endian interpretation)
    # The key might be read as uint32[4]: 0xF46E8EB4, 0xEE3ED14E, 0x75416160, 0xF49C720E
    # Those are just the same in little-endian
