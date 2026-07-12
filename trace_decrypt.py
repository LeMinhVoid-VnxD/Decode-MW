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

# Read the IAT to find function names
# IAT is typically in .rdata section
# Let's first find the import directory
rdata_va = None
rdata_off = None
rdata_size = None
for name, va, vs, ro, rs in sections:
    if name == '.rdata':
        rdata_va = va
        rdata_off = ro
        rdata_size = rs
        break

# Find IAT entries by looking up addresses used in decrypt_xxtea_b64
# The call instructions reference IAT entries
fn_rva = 0x18833F0  # decrypt_xxtea_b64
fn_off = rva2off(fn_rva)

# Read the full function (approx 200 bytes)
code = dll[fn_off:fn_off+200]

print("=== decrypt_xxtea_b64: Tracing calls and key references ===")
print()

# Track indirect calls and their targets
for i in range(0, len(code)-5, 1):
    # call [0xXXXXXXXX] - indirect call through IAT
    if i+5 < len(code) and code[i:i+2] == b'\xff\x15':
        iat_addr = struct.unpack('<I', code[i+2:i+6])[0]
        # Check if this IAT entry is in .rdata section
        iat_off = rva2off(iat_addr)
        if iat_off:
            # Read the actual function pointer from IAT
            func_rva = struct.unpack('<I', dll[iat_off:iat_off+4])[0]
            # Check if it falls within any section
            func_off = rva2off(func_rva)
            section_name = "???"
            for name, va, vs, ro, rs in sections:
                if va <= func_rva < va + vs:
                    section_name = name
                    break
            offset = fn_rva + i
            print(f"  @0x{offset:08X}: call [0x{iat_addr:08X}] -> func RVA=0x{func_rva:08X} (section: {section_name})")
    
    # mov reg, [0xXXXXXXXX] - reading a global variable
    if code[i] == 0xA1 and i+4 < len(code):
        global_rva = struct.unpack('<I', code[i+1:i+5])[0]
        global_off = rva2off(global_rva)
        section_name = "???"
        for name, va, vs, ro, rs in sections:
            if va <= global_rva < va + vs:
                section_name = name
                break
        offset = fn_rva + i
        value = None
        if global_off and global_off + 4 <= len(dll):
            value = struct.unpack('<I', dll[global_off:global_off+4])[0]
        print(f"  @0x{offset:08X}: mov eax, [0x{global_rva:08X}] (section: {section_name}) val=0x{value:X}" if value else f"  @0x{offset:08X}: mov eax, [0x{global_rva:08X}] (section: {section_name})")

# Now let's also look at EncryptBufferSimple more carefully
print()
print("=== EncryptBufferSimple: Analysis ===")
fn2_rva = 0x18830B0
fn2_off = rva2off(fn2_rva)
code2 = dll[fn2_off:fn2_off+300]

for i in range(0, len(code2)-5, 1):
    if i+5 < len(code2) and code2[i:i+2] == b'\xff\x15':
        iat_addr = struct.unpack('<I', code2[i+2:i+6])[0]
        iat_off = rva2off(iat_addr)
        if iat_off:
            func_rva = struct.unpack('<I', dll[iat_off:iat_off+4])[0]
            offset = fn2_rva + i
            print(f"  @0x{offset:08X}: call [0x{iat_addr:08X}] -> func RVA=0x{func_rva:08X}")
    # push imm32
    if code2[i] == 0x68 and i+4 < len(code2):
        val = struct.unpack('<I', code2[i+1:i+5])[0]
        offset = fn2_rva + i
        if 0x20 <= val <= 0x7E:  # printable ASCII
            try:
                char = chr(val)
                print(f"  @0x{offset:08X}: push 0x{val:08X} ; '{char}'")
            except:
                pass
    # mov reg, imm32
    if (code2[i] & 0xF8) == 0xB8 and i+4 < len(code2):
        val = struct.unpack('<I', code2[i+1:i+5])[0]
        offset = fn2_rva + i
        reg_idx = code2[i] & 0x07
        reg_names = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        if 0x20 <= val <= 0x7E:
            try:
                print(f"  @0x{offset:08X}: mov {reg_names[reg_idx]}, 0x{val:08X} ; '{chr(val)}'")
            except:
                pass

# Also search for .data section global variables referenced by DevEncrypt functions
print()
print("=== Global variables referenced by DevEncrypt ===")
# Look for all `mov eax, [addr]` and `mov [addr], eax` in the DevEncrypt code range
dev_start = 0x1881F70  # First function
dev_end = 0x18841A0    # Last function

for fn_name, fn_rva in [('DecryptBufferA', 0x1881F70), ('EncryptBufferA', 0x1882CD0),
                        ('EncryptBufferSimple', 0x18830B0), ('decrypt_xxtea_b64', 0x18833F0),
                        ('encrypt_xxtea_b64', 0x1883480), ('getSingleton', 0x1883530),
                        ('getZipPassword', 0x1883570)]:
    fn_off = rva2off(fn_rva)
    fn_code = dll[fn_off:fn_off+512]
    print(f"\n{fn_name}:")
    for i in range(0, min(len(fn_code), 300)-5, 1):
        # mov eax, [addr] (A1 xx xx xx xx)
        if fn_code[i] == 0xA1:
            addr_rva = struct.unpack('<I', fn_code[i+1:i+5])[0]
            addr_off = rva2off(addr_rva)
            sec_name = "???"
            for name, va, vs, ro, rs in sections:
                if va <= addr_rva < va + vs:
                    sec_name = name
                    break
            offset = fn_rva + i
            print(f"  @0x{offset:08X}: mov eax, [0x{addr_rva:08X}] ({sec_name})")

# Also look for any 16-byte xmmword references in .rdata or .data
print()
print("=== Searching for 16-byte constants in .rdata/.data sections ===")
for sec_name in ['.rdata', '.data']:
    for name, va, vs, ro, rs in sections:
        if name == sec_name:
            sec_data = dll[ro:ro+rs]
            # Look for 16-byte sequences that are referenced from DevEncrypt code
            # (This is complex, so let's just look for patterns)
            break
