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
scratch_base = ql.mem.map_anywhere(0x1000)

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

def assemble(instrs):
    return bytes(ks.asm(instrs)[0])

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

obfu_code_table = {}
obfu_ctrlflow = []

for target in range(num_obd):
    first = 0
    first_prev = 0
    last = num_obd - 1
    last_prev = num_obd - 1
    sum_diff = 0
    
    while True:
        index = (first + last) // 2
        xor_value = obd[index][0] ^ sum_diff
        
        if index <= target:
            if index != target:
                first = index + 1
                last = last_prev
                first_prev = first
                sum_diff = (obd[index][0] - obd[index][3]) % (1 << 32)
            else:
                break
        else:
            last = index - 1
            last_prev = last
            sum_diff = (obd[index][0] + obd[index][3]) % (1 << 32)
        
        if first > last:
            raise Exception("???")
    
    addr = image_start + xor_value
    val1 = (obd[index][1] + obd[index][0]) % (1 << 32)
    val2 = (obd[index][2] - obd[index][0]) % (1 << 32)
    val3 = (obd[index][4] + obd[index][3]) % (1 << 32)
    unk3 = obd[index][3]
    
    cont_mode = (unk3 >> 12) & 0x7F
    data_size = unk3 & 0xfff
    
    if cont_mode in [0x0B, 0x10, 0x13, 0x16, 0x33, 0x38, 0x45, 0x74]:
        # INDIRECT JUMP
        param1 = (unk3 >> 18) & 0x3F00 | (unk3 >> 12) & 0x80 | cont_mode & 0xFFF0007F | ((unk3 & 0x100000 | ((unk3 & 0x1E00000 | (unk3 >> 5) & 0x100000) >> 5)) >> 1)
        param2 = val3
        obfu_ctrlflow.append((-1, -1))
    elif cont_mode in [0x19, 0x2F, 0x58, 0x63]:
        # RETURN
        obfu_ctrlflow.append((addr, 0, 0))
    else:
        # DIRECT JUMP
        addr0 = image_start + xor_value + data_size
        addr1 = image_start + val3
        
        obfu_ctrlflow.append((addr, addr0, addr1))
    
    obfu_code_table[addr] = (index, val1, val2, val3, unk3)

def decrypt_code(ecstart):
    print("DECRYPTING CODE @ " + hex(ecstart))
    ecstart_offset = ecstart - image_start

    index, val1, val2, val3, unk3 = obfu_code_table[ecstart]
    data_size = unk3 & 0xfff
    enc_bytes = ql.mem.read(ecstart, data_size + 1)
    dec_bytes = [0] * data_size
    chksum = 0xa5

    if val2 & 0x1000000 == 0:
        print("DERIVING KEY FROM MAC")
        mac_func = mem_read_int(sym_data_inv["?g_apMacFuncs@WARBIRD@@3PAP6AXAA_JPBE1ABU_CBCKey2@1@@ZA"] + (val2 >> 25) * 4)
        
        for instr in md.disasm(ql.mem.read(mac_func, 0x100), mac_func):
            if instr.mnemonic == "ret":
                mac_end = instr.address
                break
        
        ql.mem.write(scratch_base, b"\x00\x01\x02\x03\x04\x05")
        ql.mem.write(scratch_base + 0x10, ql.pack(ecstart_offset))
        ql.mem.write(scratch_base + 0x14, ql.pack(0))
        ql.arch.stack_push(scratch_base)
        ql.arch.stack_push(val1 + image_start + (val2 & 0xffff))
        ql.arch.stack_push(val1 + image_start)
        ql.arch.stack_push(0x10)
        ql.arch.stack_push(0x69696969)
        
        old_sp = ql.arch.regs.esp
        ql.run(begin=mac_func, end=mac_end)
        ql.arch.regs.esp = old_sp
        
        key1 = ql.mem.read(0x10, 4)
        key2 = ql.mem.read(0x14, 2)
    else:
        print("USING BLOCK VALUES AS KEY")
        key1 = val1.to_bytes(4, "little")
        key2 = (val2 & 0xFFFF).to_bytes(2, "little")

    for i in range(data_size - 1, -1, -1):
        enc_byte = enc_bytes[i]
        
        if i > 0:
            b = enc_bytes[i - 1]
        else:
            b = 0
        
        if i % 2 == 1:
            if (enc_byte ^ key1[3]) % 2 == 1:
                a = (enc_byte ^ key1[3] ^ key1[2] ^ 0x100) >> 1
            else:
                a = (enc_byte ^ key1[3]) >> 1
            
            if (a ^ b) % 2 == 1:
                dec_byte = (a ^ b ^ key2[1] ^ 0x100) >> 1
            else:
                dec_byte = (a ^ b) >> 1
        else:
            if (enc_byte ^ key1[1]) % 2 == 1:
                a = (enc_byte ^ key1[1] ^ key1[0] ^ 0x100) >> 1
            else:
                a = (enc_byte ^ key1[1]) >> 1
            
            if (a ^ b) % 2 == 1:
                dec_byte = (a ^ b ^ key2[0] ^ 0x100) >> 1
            else:
                dec_byte = (a ^ b) >> 1
        
        chksum ^= dec_byte
        dec_bytes[i] = dec_byte

    if chksum != (val2 >> 16) & 0xFF:
        raise Exception("CHECKSUM FAILED!")

    print(dec_bytes)

    first = 0
    last = num_relocs - 1

    while last >= first:
        index = (first + last) // 2
        addr = private_relocs[index] & 0xFFFFFFF
        
        if ecstart_offset >= addr:
            if ecstart_offset == addr:
                first = (first + last) // 2
                break
            
            first = index + 1
        else:
            last = index - 1

    index = first

    while index < num_relocs:
        addr = private_relocs[index] & 0xFFFFFFF
        
        if addr >= (ecstart_offset + data_size):
            break
        
        offset = 0
        ofmode = (private_relocs[index] >> 28) & 3
        
        if ofmode == 1:
            offset = -ecstart % (1 << 32)
        elif ofmode == 2:
            offset = ecstart
        
        if ((private_relocs[index] >> 30) & 3) == 2 and offset != 0:
            print(f"RELOC @ OFFSET {hex(addr - ecstart_offset)} +{hex(offset)}")
            val = array_read_int(dec_bytes, addr - ecstart_offset)
            val = (val + offset) % (1 << 32)
            dec_bytes = array_write_int(dec_bytes, addr - ecstart_offset, val)
            print(dec_bytes)
        
        index += 1
    
    dec_bytes = bytes(dec_bytes)

    for instr in md.disasm(dec_bytes, 0):
        print(instr)

    return dec_bytes

def nearest_block(caddr):
    return list(filter(lambda a: a <= caddr, obfu_code_table))[-1]

def deobfu_func(ecstart):
    print("DEOBFUSCATING CODE @ " + hex(ecstart))
    ecstart_offset = ecstart - image_start
    code_chunks = []

    index, val1, val2, val3, unk3 = obfu_code_table[ecstart]
    min_index = index

    addr = 0
    max_addr = ecstart
    while addr < max_addr:
        addr, addr0, addr1 = obfu_ctrlflow[index]
        max_addr = max(max_addr, addr, addr0, addr1)
        
        if max_addr not in obfu_code_table:
            max_addr = nearest_block(max_addr)
        
        print(hex(addr), hex(max_addr))
        
        code_chunks.append(decrypt_code(addr))
        
        index += 1

    max_index = index

    ctrlflow = obfu_ctrlflow[min_index:max_index]
    code_out = b""

    for i in range(max_index - min_index):
        code_out += code_chunks[i]
        addr, addr0, addr1 = ctrlflow[i]
        unk3 = obfu_code_table[addr][4]
        cont_mode = (unk3 >> 12) & 0x7F

        if cont_mode in [0x0B, 0x10, 0x13, 0x16, 0x33, 0x38, 0x45, 0x74]:
            print("INDIRECT JUMP?")
            param1 = (unk3 >> 18) & 0x3F00 | (unk3 >> 12) & 0x80 | cont_mode & 0xFFF0007F | ((unk3 & 0x100000 | ((unk3 & 0x1E00000 | (unk3 >> 5) & 0x100000) >> 5)) >> 1)
            param2 = val3
            
            # return b""
        elif cont_mode in [0x19, 0x2F, 0x58, 0x63]:
            ret_size = (unk3 >> 21) & 0xF
            print(f"RETURN {ret_size}")
            print(hex(addr))
            
            ret_code_bin = assemble(f"ret {ret_size * 4}")
            ret_code_bin += b"\x90" * (16 - len(ret_code_bin))
            code_out += ret_code_bin
        else:
            print("DIRECT JUMP")
            jmp_code = ""
            
            # 0x01 CF
            # 0x04 PF
            # 0x10 AF
            # 0x40 ZF
            # 0x80 SF
            # 0x100 TF
            # 0x200 IF
            # 0x400 DF
            # 0x800 OF
            
            if cont_mode in [0x00, 0x34, 0x5A, 0x6C]:
                pass
                # SF == 0 -> Addr1 else Addr0
                # js addr0
                # jmp addr1
                jmp_code = "js {addr0}; jmp {addr1}"
            elif cont_mode in [0x01, 0x20, 0x2D, 0x42]:
                pass
                # ZF != 0 || SF != OF -> Addr0 else Addr1
                # jz addr0
                # jl addr0
                # jmp addr1
                jmp_code = "jz {addr0}; jl {addr0}; jmp {addr1}"
            elif cont_mode in [0x02, 0x21, 0x2E, 0x35]:
                pass
                # jmp addr1
                jmp_code = "jmp {addr1}"
            elif cont_mode in [0x03, 0x0F, 0x4A, 0x67]:
                pass
                # SF != 0 -> Addr0
                # SF == 0 && OF == 0 -> Addr0
                # SF == 0 && OF != 0 -> Addr1
                # js addr0
                # jno addr0
                # jmp addr1
                
                jmp_code = "js {addr0}; jno {addr0}; jmp {addr1}"
            elif cont_mode in [0x05, 0x11, 0x5D, 0x78]:
                pass
                # PF == 0 -> Addr1 else Addr0
                # jp addr0
                # jmp addr1
                
                jmp_code = "jp {addr0}; jmp {addr1}"
            elif cont_mode in [0x06, 0x4D, 0x54, 0x6D]:
                pass
                # ZF != 0 || SF == OF -> Addr0 else Addr1
                # jz addr0
                # jnl addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jnl {addr0}; jmp {addr1}"
            elif cont_mode in [0x07, 0x0E, 0x3C, 0x53]:
                pass
                # OF == 0 -> Addr1 else Addr0
                # jo addr0
                # jmp addr1
                
                jmp_code = "jo {addr0}; jmp {addr1}"
            elif cont_mode in [0x08, 0x0D, 0x1F, 0x5B]:
                pass
                # ZF != 0 -> Addr1
                # ZF == 0 && SF == OF -> Addr0
                # ZF == 0 && SF != OF -> Addr1
                # jz addr1
                # jl addr1
                # jmp addr0
                
                jmp_code = "jz {addr1}; jl {addr1}; jmp {addr0}"
            elif cont_mode in [0x09, 0x22, 0x25, 0x31]:
                pass
                # PF != 0 -> Addr1 else Addr0
                # jnp addr0
                # jmp addr1
                
                jmp_code = "jnp {addr0}; jmp {addr1}"
            elif cont_mode in [0x0A, 0x17, 0x24, 0x32]:
                pass
                # ZF != 0 -> Addr0
                # ZF == 0 && OF == 0 -> Addr0
                # ZF == 0 && OF != 0 -> Addr1
                # jz addr0
                # jno addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jno {addr0}; jmp {addr1}"
            elif cont_mode in [0x0C, 0x4B, 0x56, 0x65]:
                pass
                # PF && CF -> Addr1 else Addr0
                # jnp addr0
                # jnc addr0
                # jmp addr1
                
                jmp_code = "jnp {addr0}; jnc {addr0}; jmp {addr1}"
            elif cont_mode in [0x12, 0x18, 0x1D, 0x51]:
                pass
                # SF != OF -> Addr1 else Addr0
                # jnl addr0
                # jmp addr1
                
                jmp_code = "jnl {addr0}; jmp {addr1}"
            elif cont_mode in [0x14, 0x3B, 0x4F, 0x5F]:
                pass
                # OF != 0 -> Addr1 else Addr0
                # jno addr0
                # jmp addr1
                
                jmp_code = "jno {addr0}; jmp {addr1}"
            elif cont_mode in [0x15, 0x1E, 0x41, 0x55]:
                pass
                # PF == 0 -> Addr1
                # PF != 0 && ZF == OF -> Addr0
                # PF != 0 && ZF != OF -> Addr1
                # jnp addr1
                # push eax
                # push ecx
                # pushfd
                # pop eax
                # mov ecx, eax
                # shr eax, 5
                # xor eax, ecx
                # test al, 40h
                # pop eax
                # pop ecx
                # jz addr0
                # jmp addr1
            elif cont_mode in [0x1A, 0x3E, 0x60, 0x72]:
                pass
                # PF != 0 -> Addr1 else Addr0
                # jnp addr0
                # jmp addr1
                
                jmp_code = "jnp {addr0}; jmp {addr1}"
            elif cont_mode in [0x1B, 0x44, 0x48, 0x7E]:
                pass
                # ZF == 0 -> Addr1 else Addr0
                # jz addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jmp {addr1}"
            elif cont_mode in [0x1C, 0x26, 0x2B, 0x75]:
                pass
                # ZF == 0 || PF != 0 -> Addr0 else Addr1
                # jnz addr0
                # jp addr0
                # jmp addr1
                
                jmp_code = "jnz {addr0}; jp {addr0}; jmp {addr1}"
            elif cont_mode in [0x27, 0x43, 0x64, 0x6B]:
                pass
                # SF != 0 -> Addr1 else Addr0
                # jns addr0
                # jmp addr1
                
                jmp_code = "jns {addr0}; jmp {addr1}"
            elif cont_mode in [0x28, 0x40, 0x68, 0x7B]:
                pass
                # CF != 0 -> Addr1
                # CF == 0 && ZF == 0 -> Addr0
                # CF == 0 && ZF != 0 -> Addr1
                # ja addr0
                # jmp addr1
                
                jmp_code = "ja {addr0}; jmp {addr1}"
            elif cont_mode in [0x29, 0x3A, 0x71, 0x76]:
                pass
                # ZF != 0 || CF != PF -> Addr0 else Addr1
                # jz addr0
                # push eax
                # push ecx
                # pushfd
                # pop eax
                # mov ecx, eax
                # shr eax, 2
                # xor eax, ecx
                # test al, 01h
                # pop eax
                # pop ecx
                # jnz addr0
                # jmp addr1
            elif cont_mode in [0x2C, 0x30, 0x3F, 0x7C]:
                pass
                # DF == 0 -> Addr1 else Addr0
                # push eax
                # push ecx
                # pushfd
                # pop eax
                # mov ecx, eax
                # shr eax, 4
                # xor eax, ecx
                # test al, 40h
                # pop eax
                # pop ecx
                # jz addr0
                # jmp addr1
            elif cont_mode in [0x36, 0x59, 0x61, 0x7D]:
                pass
                # CF == 0 -> Addr1 else Addr0
                # jc addr0
                # jmp addr1
                
                jmp_code = "jc {addr0}; jmp {addr1}"
            elif cont_mode in [0x37, 0x52, 0x5E, 0x79]:
                pass
                # CF != 0 || ZF != 0 -> Addr0 else Addr1
                # jna addr0
                # jmp addr1
                
                jmp_code = "jna {addr0}; jmp {addr1}"
            elif cont_mode in [0x39, 0x4E, 0x6F, 0x7A]:
                pass
                # SF == OF -> Addr0 else Addr1
                # jge addr0
                # jmp addr1
                
                jmp_code = "jge {addr0}; jmp {addr1}"
            elif cont_mode in [0x46, 0x6A, 0x70, 0x77]:
                pass
                # CF != 0 -> Addr1
                # CF == 0 && OF == 0 -> Addr0
                # CF == 0 && OF != 0 -> Addr1
                # jc addr1
                # jo addr1
                # jmp addr0
                
                jmp_code = "jc {addr1}; jo {addr1}; jmp {addr0}"
            elif cont_mode in [0x47, 0x49, 0x62, 0x73]:
                pass
                # ZF != 0 -> Addr1 else Addr0
                # jnz addr0
                # jmp addr1
                
                jmp_code = "jnz {addr0}; jmp {addr1}"
            elif cont_mode in [0x4C, 0x66, 0x69, 0x7F]:
                pass
                # CF != 0 -> Addr1
                # CF == 0 && PF != 0 -> Addr0
                # CF == 0 && PF == 0 -> Addr1
                # jc addr1
                # jnp addr1
                # jmp addr0
                
                jmp_code = "jc {addr1}; jnp {addr1}; jmp {addr0}"
            elif cont_mode in [0x50, 0x57, 0x5C, 0x6E]:
                pass
                # CF != 0 -> Addr1 else Addr0
                # jnc addr0
                # jmp addr1
                
                jmp_code = "jnc {addr0}; jmp {addr1}"
            else:
                pass
                # jmp addr0
                
                jmp_code = "jmp {addr0}"
            
            print(hex(addr), hex(addr0), hex(addr1))
            block_offset0 = addr0 - nearest_block(addr0)
            block_offset1 = addr1 - nearest_block(addr1)
            
            addr0_index = obfu_code_table[addr0 - block_offset0][0] - min_index
            addr1_index = obfu_code_table[addr1 - block_offset1][0] - min_index
            
            print(addr0_index, addr1_index)
            
            jmp_code = jmp_code.format(addr0=block_offset0 + sum(map(len, code_chunks[:addr0_index])) + 16 * addr0_index - len(code_out), addr1=block_offset1 + sum(map(len, code_chunks[:addr1_index])) + 16 * addr1_index - len(code_out))
            jmp_code_bin = assemble(jmp_code)
            jmp_code_bin += b"\x90" * (16 - len(jmp_code_bin)) # dont like this but Ghidra kekw
            code_out += jmp_code_bin

    for instr in md.disasm(code_out, 0):
        print(instr)
    
    with open(hex(ecstart) + ".bin", "wb") as f:
        f.write(code_out)
    
    return code_out

# obfu_code(0x12016af)