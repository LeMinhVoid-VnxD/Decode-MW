import struct

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libSandBoxEngine.dll'
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

def rva2off(rva):
    for name, va, vs, ro, rs in sections:
        if va <= rva < va + vs:
            return rva - va + ro
    return None

def off2rva(off):
    for name, va, vs, ro, rs in sections:
        if ro <= off < ro + rs:
            return off - ro + va
    return None

# Step 1: Find cross-references to getXXTeaKey string (RVA = 0x231423A)
getxxteakey_rva = 0x231423A
getxxteakey_off = rva2off(getxxteakey_rva)
print(f"getXXTeaKey string at file offset 0x{getxxteakey_off:X}, RVA 0x{getxxteakey_rva:X}")

# Search for this RVA in .text section (where code lives)
text_va = None
text_off = None
text_size = None
for name, va, vs, ro, rs in sections:
    if name == '.text':
        text_va = va
        text_off = ro
        text_size = rs
        break

print(f".text section: VA=0x{text_va:X}, file_off=0x{text_off:X}, size=0x{text_size:X}")
print()

# Search for references to getXXTeaKey string RVA in .text
search_bytes = struct.pack('<I', getxxteakey_rva)
print(f"Searching for RVA 0x{getxxteakey_rva:08X} references in .text...")
text_data = dll[text_off:text_off+text_size]
pos = 0
while True:
    pos = text_data.find(search_bytes, pos)
    if pos == -1:
        break
    ref_rva = text_va + pos
    ref_off = text_off + pos
    print(f"  XREF at RVA=0x{ref_rva:08X} offset=0x{ref_off:X}")
    # Show surrounding code context (32 bytes)
    start = max(0, pos - 16)
    end = min(len(text_data), pos + 16 + 4)
    context = text_data[start:end]
    print(f"    Context hex: {context.hex()}")
    # Try to identify the instruction (lea reg, [addr] or mov reg, addr)
    before = text_data[max(0,pos-6):pos]
    print(f"    Before xref: {before.hex()}")
    pos += 4

# Step 2: Find DevEncrypt functions and analyze the class
print()
print("=== DevEncrypt Class Analysis ===")
dev_functions = {
    'constructor': 0x47DA70,
    'getSingleton': 0x1883530,
    'getZipPassword': 0x1883570,
    'decrypt_xxtea_b64': 0x18833F0,
    'encrypt_xxtea_b64': 0x1883480,
    'DecryptBufferA': 0x1881F70,
    'EncryptBufferA': 0x1882CD0,
    'EncryptBufferSimple': 0x18830B0,
    'DoExclusiveOR': 0x1882C40,
    'IsBufferEncrypted': 0x18832E0,
    'IsFileEncrypted': 0x18833A0,
    'DecryptFileA': 0x18825E0,
}

for name, rva in dev_functions.items():
    off = rva2off(rva)
    if off:
        # Read first 64 bytes
        code = dll[off:off+64]
        print(f"\n{name} @ RVA=0x{rva:08X} (file=0x{off:X}):")
        for i in range(0, len(code), 16):
            hex_str = ' '.join(f'{b:02x}' for b in code[i:i+16])
            print(f"  0x{rva+i:08X}: {hex_str}")

# Step 3: Also analyze the getSingleton function more fully
print()
print("=== getSingleton Full Analysis ===")
singleton_rva = 0x1883530
singleton_off = rva2off(singleton_rva)
for off_mult in [256, 512, 1024]:
    code = dll[singleton_off:singleton_off+off_mult]
    # Look for calls to other functions
    print(f"  Full {off_mult}B analysis:")
    for i in range(0, len(code)-5, 1):
        # Look for call instructions (E8 xx xx xx xx)
        if code[i] == 0xE8:
            rel_addr = struct.unpack('<i', code[i+1:i+5])[0]
            target_rva = singleton_rva + i + 5 + rel_addr
            print(f"    CALL 0x{target_rva:08X}")
        # Look for indirect calls (FF 15 xx xx xx xx)
        if i+1 < len(code) and code[i:i+2] == b'\xff\x15':
            call_addr = struct.unpack('<I', code[i+2:i+6])[0]
            print(f"    CALL [0x{call_addr:08X}]")
        # Look for mov reg, [addr] (A1 xx xx xx xx or 8B xx xx xx xx xx)
    print()
    # Early exit if we found enough
    found_calls = False
    for i in range(0, min(len(code), 200)-5, 1):
        if code[i] == 0xE8:
            found_calls = True
    if found_calls:
        break
