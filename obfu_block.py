from qiling import *
from qiling.const import *
from capstone import *
from keystone import *
import pefile
import json
import re

# Set to binary name
BIN_NAME = "sppsvc.exe"

REG_NAMES = {
    19: "EAX",
    20: "EBP",
    21: "EBX",
    22: "ECX",
    23: "EDI",
    24: "EDX",
    29: "ESI"
}
NOP = b"\x90"

with open("syms.json", "r") as f:
    sym_data = json.loads(f.read())

sym_data = {int(a, 16): b for a, b in sym_data.items()}
sym_data_inv = {b: a for a, b in sym_data.items()}
sym_addrs = sorted(sym_data)

ks = Ks(KS_ARCH_X86, KS_MODE_32)
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True
ql = Qiling(["./rootfs/sppsvc.exe"], "./rootfs", verbose=QL_VERBOSE.OFF)
image_start = ql.loader.images[0].base
image_end = ql.loader.images[0].end
image_size = image_end - image_start
pe = pefile.PE(data=ql.mem.read(image_start, image_size))

def mem_read_int(addr):
    return ql.unpack(ql.mem.read(addr, 4))

def array_read_int(array, offset):
    return int.from_bytes(array[offset:offset+4], "little")

def array_write_int(array, offset, val):
    arr_copy = list(array)
    val_bytes = val.to_bytes(4, "little")
    
    for i in range(4):
        arr_copy[offset + i] = val_bytes[i]
    
    return arr_copy

stub_frame = 0x010BE265

num_obd = mem_read_int(sym_data_inv["?g_nNumObfuscatedBlockData@WARBIRD@@3KA"])
obd_addr = sym_data_inv["?g_ObfuscatedBlockData@WARBIRD@@3PAU_OBFUSCATED_BLOCK_DATA@1@A"]
obd = []

for i in range(num_obd):
    obf_block = []
    
    for j in range(5):
        obf_block.append(mem_read_int(obd_addr + 4*(5*i + j)))
    
    obd.append(obf_block)

num_relocs = mem_read_int(sym_data_inv["?g_PrivateRelocationsTable@WARBIRD@@3VCPrivateRelocationsTable@1@B"])
reloc_addr = sym_data_inv["?g_PrivateRelocationsTable@WARBIRD@@3VCPrivateRelocationsTable@1@B"] + 4
private_relocs = []

for i in range(num_relocs):
    private_relocs.append(mem_read_int(reloc_addr + 4*i))

stub_frame_offset = stub_frame - image_start

first = 0
first_prev = first
last = num_obd - 1
last_prev = last
sum_diff = 0

while True:
    index = (first + last) // 2
    xor_value = obd[index][0] ^ sum_diff
    
    if stub_frame_offset >= xor_value:
        if stub_frame_offset >= xor_value + (obd[index][3] & 0xFFF):
            first = index + 1
            last = last_prev
            first_prev = first
            sum_diff = (obd[index][0] - obd[index][3]) % (1 << 32)
        else:
            print(f"XOR {hex(xor_value)} SUMDIFF {hex(sum_diff)} INDEX {hex(index)}")
            break
    else:
        last = index - 1
        last_prev = last
        sum_diff = (obd[index][0] + obd[index][3]) % (1 << 32)
    
    if first > last:
        raise Exception("Offset not found in block table!")
    
    print(f"XOR {hex(xor_value)} SUMDIFF {hex(sum_diff)} INDEX {hex(index)}")

val1 = (obd[index][1] + obd[index][0]) % (1 << 32)
val2 = (obd[index][2] - obd[index][0]) % (1 << 32)
val3 = (obd[index][4] + obd[index][3]) % (1 << 32)
unk3 = obd[index][3]
data_size = unk3 & 0xfff
xor_plus_binstart = image_start + xor_value
val1_bytes = val1.to_bytes(4, "little")
val2_bytes = val2.to_bytes(4, "little")
enc_bytes = ql.mem.read(xor_plus_binstart, data_size + 1)
dec_bytes = [0] * data_size
chksum = 0xa5

if val2 & 0x1000000 == 0:
    raise Exception("USES MAC-DERIVED KEY")

for i in range(data_size - 1, -1, -1):
    enc_byte = enc_bytes[i]
    
    if i > 0:
        b = enc_bytes[i - 1]
    else:
        b = 0
    
    if i % 2 == 1:
        if (enc_byte ^ val1_bytes[3]) % 2 == 1:
            a = (enc_byte ^ val1_bytes[3] ^ val1_bytes[2] ^ 0x100) >> 1
        else:
            a = (enc_byte ^ val1_bytes[3]) >> 1
        
        if (a ^ b) % 2 == 1:
            dec_byte = (a ^ b ^ val2_bytes[1] ^ 0x100) >> 1
        else:
            dec_byte = (a ^ b) >> 1
    else:
        if (enc_byte ^ val1_bytes[1]) % 2 == 1:
            a = (enc_byte ^ val1_bytes[1] ^ val1_bytes[0] ^ 0x100) >> 1
        else:
            a = (enc_byte ^ val1_bytes[1]) >> 1
        
        if (a ^ b) % 2 == 1:
            dec_byte = (a ^ b ^ val2_bytes[0] ^ 0x100) >> 1
        else:
            dec_byte = (a ^ b) >> 1
    
    chksum ^= dec_byte
    dec_bytes[i] = dec_byte

if chksum != val2_bytes[2]:
    raise Exception("CHECKSUM FAILED!")

print(dec_bytes)

first = 0
last = num_relocs - 1

while last >= first:
    index = (first + last) // 2
    addr = private_relocs[index] & 0xFFFFFFF
    
    if xor_value >= addr:
        if xor_value == addr:
            first = (first + last) // 2
            break
        
        first = index + 1
    else:
        last = index - 1

index = first

while index < num_relocs:
    addr = private_relocs[index] & 0xFFFFFFF
    
    if addr >= (xor_value + data_size):
        break
    
    offset = 0
    ofmode = (private_relocs[index] >> 28) & 3
    
    if ofmode == 1:
        offset = -xor_plus_binstart % (1 << 32)
    elif ofmode == 2:
        offset = xor_plus_binstart
    elif ofmode == 3:
        offset = 0
    
    if ((private_relocs[index] >> 30) & 3) == 2:
        print(hex(addr - xor_value), hex(offset))
        val = array_read_int(dec_bytes, addr - xor_value)
        val = (val + offset) % (1 << 32)
        dec_bytes = array_write_int(dec_bytes, addr - xor_value, val)
        print(dec_bytes)
    
    index += 1

dec_bytes = bytes(dec_bytes)

for instr in md.disasm(dec_bytes, 0):
    print(instr)