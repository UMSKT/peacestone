from qiling import *
from qiling.const import *
from capstone import *
from keystone import *
import pefile
import json
import re
import numpy as np

# Set to binary name
BIN_NAME = "sppsvc.exe"

# Set to function to be analyzed
# ANLZ_FUNC = "?VerifyPKeyByInstalledPidConfig@CSLSLicenseManager@@IBEJPAVCSLPKey@@PBGPAUtagPKEY_BASIC_INFO@@PAPAGPAUDECODED_PKEY_DATA@@@Z"
ANLZ_FUNC = "_wmain"

# These magic regexes are derived from the byte markers in notes.txt
PUSH_REGEX = rb"(?:\x8dd\$\xfc\x89[\x04\x0c\x14\x1c,4<]\$|[PQRSUVW]){2}\x8d[x\x05\r\x15\x1d-5=].{4}"
STUB_RET4_REGEX = rb"\x8b[DLT\\lt\|]\$\x04\xc2\x04\x00"
STUB_RET0_REGEX = rb"\x87[\x04\x0c\x14\x1c,4<]\$\xc3"
STUB_MAX_SIZE = 0x40 # Maximum size of jump stub

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
ql = Qiling(["./rootfs/sppsvc.exe"], "./rootfs")
image_start = ql.loader.images[0].base
image_end = ql.loader.images[0].end
image_size = image_end - image_start
pe = pefile.PE(data=ql.mem.read(image_start, image_size))

num_obd = ql.unpack(ql.mem.read(sym_data_inv["?g_nNumObfuscatedBlockData@WARBIRD@@3KA"], 4))
obd_addr = sym_data_inv["?g_ObfuscatedBlockData@WARBIRD@@3PAU_OBFUSCATED_BLOCK_DATA@1@A"]
obd = []

for i in range(num_obd):
    obf_block = []
    
    for j in range(5):
        obf_block.append(ql.unpack(ql.mem.read(obd_addr + 4*(5*i + j), 4)))
    
    obd.append(obf_block)

stub_frame = 0x120f989
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

for i in range(data_size - 1, 0, -1):
    enc_byte = enc_bytes[i]
    b = enc_bytes[i - 1]
    
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
    print(hex(dec_byte))
    dec_bytes[i] = dec_byte