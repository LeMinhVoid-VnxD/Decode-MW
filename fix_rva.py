import struct

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libSandBoxEngine.dll'
with open(dll_path, 'rb') as f:
    dll = f.read()

pe_offset = struct.unpack('<I', dll[0x3C:0x40])[0]
num_sections = struct.unpack('<H', dll[pe_offset+6:pe_offset+8])[0]
opt_hdr_size = struct.unpack('<H', dll[pe_offset+20:pe_offset+22])[0]
section_start = pe_offset + 24 + opt_hdr_size

# Read ImageBase from optional header
opt_hdr = dll[pe_offset+24:pe_offset+24+opt_hdr_size]
magic = struct.unpack('<H', opt_hdr[0:2])[0]
if magic == 0x10B:  # PE32
    image_base = struct.unpack('<I', opt_hdr[28:32])[0]
    print(f"PE32 ImageBase: 0x{image_base:08X}")
elif magic == 0x20B:  # PE32+
    image_base = struct.unpack('<Q', opt_hdr[24:32])[0]
    print(f"PE32+ ImageBase: 0x{image_base:016X}")

sections = []
for i in range(num_sections):
    sec = dll[section_start + i*40 : section_start + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('ascii', errors='replace')
    virt_size = struct.unpack('<I', sec[8:12])[0]
    virt_addr = struct.unpack('<I', sec[12:16])[0]
    raw_size = struct.unpack('<I', sec[16:20])[0]
    raw_off = struct.unpack('<I', sec[20:24])[0]
    sections.append((name, virt_addr, virt_size, raw_off, raw_size))
    print(f"  {name}: VA=0x{virt_addr:08X} RawOff=0x{raw_off:X}")

def rva2off(rva):
    for name, va, vs, ro, rs in sections:
        if va <= rva < va + vs:
            return rva - va + ro
    return None

# Now let's look at the absolute addresses in the DevEncrypt functions
# and subtract image_base to get the real RVA
print()
print("=== DevEncrypt references (with ImageBase correction) ===")
for fn_name, fn_rva in [('DecryptBufferA', 0x1881F70), ('EncryptBufferA', 0x1882CD0),
                        ('EncryptBufferSimple', 0x18830B0), ('decrypt_xxtea_b64', 0x18833F0),
                        ('encrypt_xxtea_b64', 0x1883480), ('getSingleton', 0x1883530),
                        ('getZipPassword', 0x1883570)]:
    fn_off = rva2off(fn_rva)
    fn_code = dll[fn_off:fn_off+256]
    print(f"\n{fn_name} @ RVA 0x{fn_rva:08X}:")
    for i in range(0, min(len(fn_code), 200)-5, 1):
        # mov eax, [addr] (A1 xx xx xx xx)
        if fn_code[i] == 0xA1:
            abs_addr = struct.unpack('<I', fn_code[i+1:i+5])[0]
            # Subtract image_base to get RVA
            rva = abs_addr - image_base if abs_addr >= image_base else abs_addr
            off = rva2off(rva)
            sec_name = "???"
            for name, va, vs, ro, rs in sections:
                if va <= rva < va + vs:
                    sec_name = name
                    break
            offset = fn_rva + i
            if off:
                # Read 16 bytes at this location
                data = dll[off:off+16]
                print(f"  @0x{offset:08X}: mov eax, [0x{abs_addr:08X}] -> RVA=0x{rva:08X} ({sec_name}) data={data.hex()}")
            else:
                print(f"  @0x{offset:08X}: mov eax, [0x{abs_addr:08X}] -> RVA=0x{rva:08X} ({sec_name}) [OUT OF BOUNDS]")
        
        # mov [addr], reg (A3 xx xx xx xx)
        if fn_code[i] == 0xA3:
            abs_addr = struct.unpack('<I', fn_code[i+1:i+5])[0]
            rva = abs_addr - image_base if abs_addr >= image_base else abs_addr
            off = rva2off(rva)
            sec_name = "???"
            for name, va, vs, ro, rs in sections:
                if va <= rva < va + vs:
                    sec_name = name
                    break
            offset = fn_rva + i
            print(f"  @0x{offset:08X}: mov [0x{abs_addr:08X}], reg -> RVA=0x{rva:08X} ({sec_name})")

# Now let's look at the IAT entries more carefully
# The indirect calls use [0xXXXXXXXX] addresses which are IAT entries
# These are typically in .rdata section
print()
print("=== IAT calls from DevEncrypt functions ===")
for fn_name, fn_rva in [('decrypt_xxtea_b64', 0x18833F0), ('encrypt_xxtea_b64', 0x1883480)]:
    fn_off = rva2off(fn_rva)
    fn_code = dll[fn_off:fn_off+200]
    print(f"\n{fn_name}:")
    for i in range(0, len(fn_code)-5, 1):
        if fn_code[i:i+2] == b'\xff\x15':
            iat_abs = struct.unpack('<I', fn_code[i+2:i+6])[0]
            iat_rva = iat_abs - image_base if iat_abs >= image_base else iat_abs
            iat_off = rva2off(iat_rva)
            if iat_off:
                func_abs = struct.unpack('<I', dll[iat_off:iat_off+4])[0]
                func_rva = func_abs - image_base if func_abs >= image_base else func_abs
                # Try to identify this function
                offset = fn_rva + i
                # Check if it's a known DLL API
                print(f"  @0x{offset:08X}: call [0x{iat_abs:08X}] -> func=0x{func_rva:08X}")

# Let's also look at what happens around the `push 0x10` in EncryptBufferSimple
# (the key size) - this might tell us where the key comes from
print()
print("=== EncryptBufferA key reference trace ===")
fn_off = rva2off(0x1882CD0)
code = dll[fn_off:fn_off+512]
for i in range(0, len(code)-9, 1):
    # Look for push 0x10 (key size = 16)
    if code[i] == 0x6A and code[i+1] == 0x10:
        offset = 0x1882CD0 + i
        context = code[max(0,i-20):i+20]
        print(f"\n  push 0x10 at 0x{offset:08X}:")
        print(f"  Context: {context.hex()}")
        # Look backwards for lea instructions 
        for j in range(max(0,i-40), i):
            if code[j] == 0x8d:  # lea
                modrm = code[j+1]
                reg = modrm >> 3 & 7
                reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                print(f"    lea at -{i-j}B: 8d {modrm:02x} {code[j+2]:02x} {code[j+3]:02x} {code[j+4]:02x}")

# Search for "hello-miniworld" or similar key derivation strings
print()
print("=== Searching for known key derivation strings ===")
for s in [b'hello-miniworld', b'miniworld', b'mini world', b'RainbowMini', b'RainbowMiniMastPc']:
    pos = 0
    while True:
        pos = dll.find(s, pos)
        if pos == -1:
            break
        # Check if in .rdata or .data
        for name, va, vs, ro, rs in sections:
            if ro <= pos < ro + rs:
                print(f'  "{s.decode()}" @ file 0x{pos:X} section {name}')
                break
        pos += 1
