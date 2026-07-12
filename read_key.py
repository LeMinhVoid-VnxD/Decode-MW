import struct

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libMiniBaseEngine.dll'
with open(dll_path, 'rb') as f:
    dll = f.read()

pe_offset = struct.unpack('<I', dll[0x3C:0x40])[0]
num_sections = struct.unpack('<H', dll[pe_offset+6:pe_offset+8])[0]
opt_hdr_size = struct.unpack('<H', dll[pe_offset+20:pe_offset+22])[0]
section_start = pe_offset + 24 + opt_hdr_size

sections = []
for i in range(num_sections):
    sec = dll[section_start + i*40 : section_start + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('ascii', errors='replace')
    virt_size = struct.unpack('<I', sec[8:12])[0]
    virt_addr = struct.unpack('<I', sec[12:16])[0]
    raw_size = struct.unpack('<I', sec[16:20])[0]
    raw_off = struct.unpack('<I', sec[20:24])[0]
    sections.append((name, virt_addr, virt_size, raw_off, raw_size))
    print(f"  {name}: VA=0x{virt_addr:08X} VSz=0x{virt_size:X} RawOff=0x{raw_off:X} RawSz=0x{raw_size:X}")

def rva2off(rva):
    for name, va, vs, ro, rs in sections:
        if va <= rva < va + vs:
            return rva - va + ro
    return None

# The address returned by getXXTeaKey
image_base = 0x10000000
returned_addr = 0x10715808
key_rva = returned_addr - image_base  # 0x00715808

print(f"\ngetXXTeaKey returns: 0x{returned_addr:08X}")
print(f"RVA: 0x{key_rva:08X}")

key_off = rva2off(key_rva)
if key_off:
    print(f"File offset: 0x{key_off:X}")
    # Read the pointer at this location (it's likely a pointer to a string)
    ptr_val = struct.unpack('<I', dll[key_off:key_off+4])[0]
    print(f"Content at location: 0x{ptr_val:08X}")
    ptr_rva = ptr_val - image_base
    print(f"  As RVA: 0x{ptr_rva:08X}")
    
    ptr_off = rva2off(ptr_rva)
    if ptr_off:
        print(f"  File offset: 0x{ptr_off:X}")
        # Try to read as string
        end = min(len(dll), ptr_off + 128)
        data = dll[ptr_off:end]
        print(f"  Raw bytes: {data[:64].hex()}")
        try:
            s = data[:data.index(b'\x00')].decode('ascii', errors='replace')
            print(f"  ASCII string: \"{s}\"")
        except:
            pass
        try:
            s = data[:data.index(b'\x00')].decode('utf-8', errors='replace')
            print(f"  UTF-8 string: \"{s}\"")
        except:
            pass
else:
    print(f"Could not resolve RVA 0x{key_rva:08X} to file offset")
    # It might be between sections - check
    for name, va, vs, ro, rs in sections:
        if va <= key_rva < va + vs:
            print(f"  Found in {name}")
            break
    else:
        print(f"  NOT in any section!")
        for name, va, vs, ro, rs in sections:
            print(f"    {name}: [0x{va:08X}, 0x{va+vs:08X})")

# Also dump the surrounding context at the address
print(f"\n=== Memory around RVA 0x{key_rva:08X} (potential key struct/pointer) ===")
if key_off:
    start = max(0, key_off - 16)
    end = min(len(dll), key_off + 64)
    for i in range(start, end, 16):
        addr = key_rva + (i - key_off)
        hex_str = ' '.join(f'{b:02x}' for b in dll[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in dll[i:i+16])
        tag = " <-- getXXTeaKey return ptr" if i == key_off else ""
        print(f"  0x{addr:08X}: {hex_str:48s} {ascii_str}{tag}")

# Read the key RVA area more carefully
# Since the returned RVA is 0x715808, and .rdata spans VA=0x6F2000-VSz=0x22CDCA
# Let's check if there are any references to this location
print(f"\n=== Looking for cross references to 0x{key_rva:08X} ===")
search_bytes = struct.pack('<I', returned_addr)
pos = 0
count = 0
while True:
    pos = dll.find(search_bytes, pos)
    if pos == -1:
        break
    for name, va, vs, ro, rs in sections:
        if ro <= pos < ro + rs:
            code_rva = pos - ro + va
            print(f"  Found 0x{returned_addr:08X} at offset 0x{pos:X} (RVA 0x{code_rva:08X}, section {name})")
            count += 1
            break
    pos += 1
print(f"  Total cross-references: {count}")

# Read the actual encoded Lua file to see its format
print(f"\n=== Checking blackboard.lua for a0817i format ===")
try:
    with open(r'C:\Users\Le Minh\AppData\Roaming\miniworddata410\data\customai_offical\CustomAI1\13b6899c84914e57908d648fefaa0d29\code\blackboard.lua', 'rb') as f:
        content = f.read()
    print(f"  First 36 bytes: {content[:36].hex()}")
    print(f"  Sign: {content[:6]}")
    # Decode the rest as base64
    b64_data = content[6:]
    print(f"  Base64 length: {len(b64_data)}")
    # Try to decode base64
    import base64
    try:
        raw = base64.b64decode(b64_data)
        print(f"  Decoded raw length: {len(raw)} bytes")
        print(f"  Raw hex: {raw[:64].hex()}")
    except Exception as e:
        print(f"  Base64 decode failed: {e}")
except FileNotFoundError:
    print(f"  File not found, looking for other test files...")
