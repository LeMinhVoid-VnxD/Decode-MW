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
            offset = rva - va + ro
            if offset < len(dll):
                return offset
    return None

def off2rva(off):
    for name, va, vs, ro, rs in sections:
        if ro <= off < ro + rs:
            return off - ro + va
    return None

# Analyze the decrypt_xxtea_b64 function
fn_name = 'decrypt_xxtea_b64'
fn_rva = 0x18833F0
fn_off = rva2off(fn_rva)
print(f'{fn_name} at file offset 0x{fn_off:X}')

# Read more code bytes
fn_size = 512
fn_code = dll[fn_off:fn_off+fn_size]
print(f'Code ({len(fn_code)} bytes):')
for i in range(0, len(fn_code), 16):
    addr = fn_rva + i
    hex_str = ' '.join(f'{b:02x}' for b in fn_code[i:i+16])
    print(f'  0x{addr:08X}: {hex_str}')

# Also analyze getZipPassword and EncryptBufferSimple
print()
for name, rva in [('getZipPassword', 0x1883570), ('EncryptBufferSimple', 0x18830B0), ('EncryptBufferA', 0x1882CD0), ('DecryptBufferA', 0x1881F70)]:
    off = rva2off(rva)
    if off:
        code = dll[off:off+512]
        print(f'{name} at file offset 0x{off:X} ({len(code)} bytes):')
        for i in range(0, min(len(code), 128), 16):
            addr = rva + i
            hex_str = ' '.join(f'{b:02x}' for b in code[i:i+16])
            print(f'  0x{addr:08X}: {hex_str}')
        print()

# Now let's also search for any constants that could be a key
# Search for XOR keys, or known constants
# Look for the typical XXTEA delta constant 0x9E3779B9
print('Searching for XXTEA delta constant 0x9E3779B9...')
delta_bytes = struct.pack('<I', 0x9E3779B9)
pos = 0
while True:
    pos = dll.find(delta_bytes, pos)
    if pos == -1:
        break
    rva_ = off2rva(pos)
    # Check if in .text section
    in_text = False
    for name, va, vs, ro, rs in sections:
        if ro <= pos < ro + rs and name == '.text':
            in_text = True
            break
    context = dll[max(0,pos-8):pos+8]
    print(f'  Delta at 0x{pos:X} (RVA=0x{rva_:X}) in_text={in_text} ctx={context.hex()}')
    pos += 4
