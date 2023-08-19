from qiling import *
from qiling.const import *
from capstone import *
from keystone import *
from subprocess import run, PIPE
import pefile
import json
import re
import os
import sys
import struct

BIN_NAME = sys.argv[1]

# These magic regexes are derived from the byte markers in notes.txt
PUSH_REGEX = rb"(?:\x8dd\$\xfc\x89[\x04\x0c\x14\x1c,4<]\$|[PQRSUVW]){2}\x8d[x\x05\r\x15\x1d-5=].{4}"
STUB_RET4_REGEX = rb"\x8b[DLT\\lt\|]\$\x04\xc2\x04\x00"
STUB_RET0_REGEX = rb"\x87[\x04\x0c\x14\x1c,4<]\$\xc3"

REG_NAMES = {
    19: "EAX",
    20: "EBP",
    21: "EBX",
    22: "ECX",
    23: "EDI",
    24: "EDX",
    29: "ESI"
}

INDIR_REGS = ["ECX", "EDI", "EBX", "EBP", "ESP", "EAX", "ESI", "EDX"]

ks = Ks(KS_ARCH_X86, KS_MODE_32)
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True
ql = Qiling([f"./{BIN_NAME}"], ".", verbose=QL_VERBOSE.DISABLED)
image_start = ql.loader.images[0].base
image_end = ql.loader.images[0].end
image_size = image_end - image_start
pe = pefile.PE(data=ql.mem.read(image_start, image_size))
scratch_base = ql.mem.map_anywhere(0x1000)

def load_syms():
    text = run(["llvm-pdbutil", "pretty", "-externals", BIN_NAME.replace(".dll", ".pdb").replace(".exe", ".pdb"), f"-load-address={hex(image_start)}"], stdout=PIPE).stdout.decode("utf-8")
    symdata = re.findall(r" public \[(\w+)\] (\S+)", text, re.MULTILINE)

    addrs = []
    unique_syms = []

    for addr, sym in symdata:
        if addr not in addrs:
            unique_syms.append((int(addr, 16), sym))
            addrs.append(addr)

    unique_syms = dict(unique_syms)
    
    return unique_syms

sym_data = load_syms()
sym_data_inv = {b: a for a, b in sym_data.items()}
sym_addrs = sorted(sym_data)

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
        obfu_ctrlflow.append((addr, param1, param2))
    elif cont_mode in [0x19, 0x2F, 0x58, 0x63]:
        # RETURN
        obfu_ctrlflow.append((addr, 0, 0))
    else:
        # DIRECT JUMP
        addr0 = image_start + xor_value + data_size
        addr1 = image_start + val3
        
        obfu_ctrlflow.append((addr, addr0, addr1))
    
    obfu_code_table[addr] = (index, val1, val2, val3, unk3)

def decrypt_code(ecstart, start_offset=0, print_code=False):
    # print("DECRYPTING CODE @ " + hex(ecstart) + " OFFSET " + hex(start_offset))
    ecstart_offset = ecstart - image_start

    index, val1, val2, val3, unk3 = obfu_code_table[ecstart]
    data_size = unk3 & 0xfff
    enc_bytes = ql.mem.read(ecstart, data_size + 1)
    dec_bytes = [0] * data_size
    chksum = 0xa5

    if val2 & 0x1000000 == 0:
        # print("DERIVING KEY FROM MAC")
        mac_func = mem_read_int(sym_data_inv["?g_apMacFuncs@WARBIRD@@3PAP6AXAA_JPBE1ABU_CBCKey2@1@@ZA"] + (val2 >> 25) * 4)
        
        for instr in md.disasm(ql.mem.read(mac_func, 0x100), mac_func):
            if instr.mnemonic == "ret":
                mac_end = instr.address
                break
        
        old_sp = ql.arch.regs.esp
        ql.mem.write(scratch_base, b"\x00\x01\x02\x03\x04\x05")
        ql.mem.write(scratch_base + 0x10, ql.pack(ecstart_offset))
        ql.mem.write(scratch_base + 0x14, ql.pack(0))
        ql.arch.stack_push(scratch_base)
        ql.arch.stack_push(val1 + image_start + (val2 & 0xffff))
        ql.arch.stack_push(val1 + image_start)
        ql.arch.stack_push(0x10)
        ql.arch.stack_push(0x69696969)
        
        ql.run(begin=mac_func, end=mac_end)
        ql.arch.regs.esp = old_sp
        
        key1 = ql.mem.read(0x10, 4)
        key2 = ql.mem.read(0x14, 2)
    else:
        # print("USING BLOCK VALUES AS KEY")
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

    # print(dec_bytes)

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
            # print(f"RELOC @ OFFSET {hex(addr - ecstart_offset)} +{hex(offset)}")
            val = array_read_int(dec_bytes, addr - ecstart_offset)
            val = (val + offset - start_offset) % (1 << 32)
            dec_bytes = array_write_int(dec_bytes, addr - ecstart_offset, val)
            # print(dec_bytes)
        
        index += 1
    
    dec_bytes = bytes(dec_bytes)
    
    if print_code:
        for instr in md.disasm(dec_bytes, start_offset):
            print(instr)
    
    return dec_bytes

def nearest_block(caddr):
    try:
        return list(filter(lambda a: a <= caddr, obfu_code_table))[-1]
    except:
        raise Exception(hex(caddr))

def deobfu_func(ecstart, start_offset=0, print_code=False):
    # print("DEOBFUSCATING CODE @ " + hex(ecstart))
    ecstart_offset = ecstart - image_start
    index, val1, val2, val3, unk3 = obfu_code_table[ecstart]
    addr = obfu_ctrlflow[index][0]
    
    # control flow is given as list of graph nodes
    # indirect jump and return nodes are treated as having no children
    
    visited_blocks = [addr]
    queue = [addr]
    
    while len(queue) > 0:
        if print_code:
            print(queue)
        
        addr = queue.pop(0)
        try:
            index = obfu_code_table[addr][0]
            cont_mode = (obfu_code_table[addr][4] >> 12) & 0x7F
            #print(hex(cont_mode))
        except:
            raise Exception(hex(addr))
        addr, addr0, addr1 = obfu_ctrlflow[index]
        
        if cont_mode not in [0x0B, 0x10, 0x13, 0x16, 0x33, 0x38, 0x45, 0x74]:
            for a in [addr0, addr1]:
                #print(a)
                if a > 0:
                    b = nearest_block(a)
                    #print(b)
                    if b not in visited_blocks and b != addr:
                        visited_blocks.append(b)
                        queue.append(b)

    # visited_blocks = sorted(visited_blocks)
    visited_indexes = list(map(lambda b: obfu_code_table[b][0], visited_blocks))
    block_sizes = list(map(lambda b: obfu_code_table[b][4] & 0xFFF, visited_blocks))
    code_out = b""

    for i in visited_indexes:
        addr, addr0, addr1 = obfu_ctrlflow[i]
        code_out += decrypt_code(addr, len(code_out) + start_offset, print_code)
        unk3 = obfu_code_table[addr][4]
        cont_mode = (unk3 >> 12) & 0x7F

        if cont_mode in [0x0B, 0x10, 0x13, 0x16, 0x33, 0x38, 0x45, 0x74]:
            # print("INDIRECT JUMP")
            param1 = addr0
            param2 = addr1
            
            base_reg = INDIR_REGS[(param1 >> 8) & 7]
            index_reg = INDIR_REGS[(param1 >> 15) & 7]
            scale = mem_read_int(sym_data_inv["?Scale@WARBIRD@@3PAKA"] + 4 * ((param1 >> 12) & 3))
            disp = param2
            
            if param1 & 0x80000 != 0:
                disp += image_start
            
            jmp_operand = ""
            
            if cont_mode in [0x0B, 0x10, 0x16, 0x74]:
                jmp_operand += hex(disp)
                
                if param1 & 0x80 != 0:
                    jmp_operand += f"+{base_reg}"
                if param1 & 0x4000 != 0:
                    jmp_operand += f"+{scale}*{index_reg}"
            elif cont_mode in [0x13, 0x33, 0x38, 0x45]:
                jmp_operand = base_reg
            
            jmp_code_bin = assemble(f"jmp [{jmp_operand}]")
            jmp_code_bin += b"\x90" * (16 - len(jmp_code_bin))
            code_out += jmp_code_bin
        elif cont_mode in [0x19, 0x2F, 0x58, 0x63]:
            ret_size = (unk3 >> 21) & 0xF
            # print(f"RETURN {ret_size}")
            # print(hex(addr))
            
            ret_code_bin = assemble(f"ret {ret_size * 4}")
            ret_code_bin += b"\x90" * (16 - len(ret_code_bin))
            code_out += ret_code_bin
        else:
            # print("DIRECT JUMP")
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
                # SF == 0 -> Addr1 else Addr0
                # js addr0
                # jmp addr1
                jmp_code = "js {addr0}; jmp {addr1}"
            elif cont_mode in [0x01, 0x20, 0x2D, 0x42]:
                # ZF != 0 || SF != OF -> Addr0 else Addr1
                # jz addr0
                # jl addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jl {addr0}; jmp {addr1}"
            elif cont_mode in [0x02, 0x21, 0x2E, 0x35]:
                # jmp addr1
                
                jmp_code = "jmp {addr1}"
            elif cont_mode in [0x03, 0x0F, 0x4A, 0x67]:
                # SF != 0 -> Addr0
                # SF == 0 && OF == 0 -> Addr0
                # SF == 0 && OF != 0 -> Addr1
                # js addr0
                # jno addr0
                # jmp addr1
                
                jmp_code = "js {addr0}; jno {addr0}; jmp {addr1}"
            elif cont_mode in [0x05, 0x11, 0x5D, 0x78]:
                # PF == 0 -> Addr1 else Addr0
                # jp addr0
                # jmp addr1
                
                jmp_code = "jp {addr0}; jmp {addr1}"
            elif cont_mode in [0x06, 0x4D, 0x54, 0x6D]:
                # ZF != 0 || SF == OF -> Addr0 else Addr1
                # jz addr0
                # jnl addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jnl {addr0}; jmp {addr1}"
            elif cont_mode in [0x07, 0x0E, 0x3C, 0x53]:
                # OF == 0 -> Addr1 else Addr0
                # jo addr0
                # jmp addr1
                
                jmp_code = "jo {addr0}; jmp {addr1}"
            elif cont_mode in [0x08, 0x0D, 0x1F, 0x5B]:
                # ZF != 0 -> Addr1
                # ZF == 0 && SF == OF -> Addr0
                # ZF == 0 && SF != OF -> Addr1
                # jz addr1
                # jl addr1
                # jmp addr0
                
                jmp_code = "jz {addr1}; jl {addr1}; jmp {addr0}"
            elif cont_mode in [0x09, 0x22, 0x25, 0x31]:
                # PF != 0 -> Addr1 else Addr0
                # jnp addr0
                # jmp addr1
                
                jmp_code = "jnp {addr0}; jmp {addr1}"
            elif cont_mode in [0x0A, 0x17, 0x24, 0x32]:
                # ZF != 0 -> Addr0
                # ZF == 0 && OF == 0 -> Addr0
                # ZF == 0 && OF != 0 -> Addr1
                # jz addr0
                # jno addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jno {addr0}; jmp {addr1}"
            elif cont_mode in [0x0C, 0x4B, 0x56, 0x65]:
                # PF && CF -> Addr1 else Addr0
                # jnp addr0
                # jnc addr0
                # jmp addr1
                
                jmp_code = "jnp {addr0}; jnc {addr0}; jmp {addr1}"
            elif cont_mode in [0x12, 0x18, 0x1D, 0x51]:
                # SF != OF -> Addr1 else Addr0
                # jnl addr0
                # jmp addr1
                
                jmp_code = "jnl {addr0}; jmp {addr1}"
            elif cont_mode in [0x14, 0x3B, 0x4F, 0x5F]:
                # OF != 0 -> Addr1 else Addr0
                # jno addr0
                # jmp addr1
                
                jmp_code = "jno {addr0}; jmp {addr1}"
            elif cont_mode in [0x15, 0x1E, 0x41, 0x55]:
                # PF == 0 -> Addr1
                # PF != 0 && ZF == OF -> Addr0
                # PF != 0 && ZF != OF -> Addr1
                
                raise Exception("Invalid continuation mode")
            elif cont_mode in [0x1A, 0x3E, 0x60, 0x72]:
                # PF != 0 -> Addr1 else Addr0
                # jnp addr0
                # jmp addr1
                
                jmp_code = "jnp {addr0}; jmp {addr1}"
            elif cont_mode in [0x1B, 0x44, 0x48, 0x7E]:
                # ZF == 0 -> Addr1 else Addr0
                # jz addr0
                # jmp addr1
                
                jmp_code = "jz {addr0}; jmp {addr1}"
            elif cont_mode in [0x1C, 0x26, 0x2B, 0x75]:
                # ZF == 0 || PF != 0 -> Addr0 else Addr1
                # jnz addr0
                # jp addr0
                # jmp addr1
                
                jmp_code = "jnz {addr0}; jp {addr0}; jmp {addr1}"
            elif cont_mode in [0x27, 0x43, 0x64, 0x6B]:
                # SF != 0 -> Addr1 else Addr0
                # jns addr0
                # jmp addr1
                
                jmp_code = "jns {addr0}; jmp {addr1}"
            elif cont_mode in [0x28, 0x40, 0x68, 0x7B]:
                # CF != 0 -> Addr1
                # CF == 0 && ZF == 0 -> Addr0
                # CF == 0 && ZF != 0 -> Addr1
                # ja addr0
                # jmp addr1
                
                jmp_code = "ja {addr0}; jmp {addr1}"
            elif cont_mode in [0x29, 0x3A, 0x71, 0x76]:
                # ZF != 0 || CF != PF -> Addr0 else Addr1
                
                raise Exception("Invalid continuation mode")
            elif cont_mode in [0x2C, 0x30, 0x3F, 0x7C]:
                # DF == 0 -> Addr1 else Addr0
                
                raise Exception("Invalid continuation mode")
            elif cont_mode in [0x36, 0x59, 0x61, 0x7D]:
                # CF == 0 -> Addr1 else Addr0
                # jc addr0
                # jmp addr1
                
                jmp_code = "jc {addr0}; jmp {addr1}"
            elif cont_mode in [0x37, 0x52, 0x5E, 0x79]:
                # CF != 0 || ZF != 0 -> Addr0 else Addr1
                # jna addr0
                # jmp addr1
                
                jmp_code = "jna {addr0}; jmp {addr1}"
            elif cont_mode in [0x39, 0x4E, 0x6F, 0x7A]:
                # SF == OF -> Addr0 else Addr1
                # jge addr0
                # jmp addr1
                
                jmp_code = "jge {addr0}; jmp {addr1}"
            elif cont_mode in [0x46, 0x6A, 0x70, 0x77]:
                # CF != 0 -> Addr1
                # CF == 0 && OF == 0 -> Addr0
                # CF == 0 && OF != 0 -> Addr1
                # jc addr1
                # jo addr1
                # jmp addr0
                
                jmp_code = "jc {addr1}; jo {addr1}; jmp {addr0}"
            elif cont_mode in [0x47, 0x49, 0x62, 0x73]:
                # ZF != 0 -> Addr1 else Addr0
                # jnz addr0
                # jmp addr1
                
                jmp_code = "jnz {addr0}; jmp {addr1}"
            elif cont_mode in [0x4C, 0x66, 0x69, 0x7F]:
                # CF != 0 -> Addr1
                # CF == 0 && PF != 0 -> Addr0
                # CF == 0 && PF == 0 -> Addr1
                # jc addr1
                # jnp addr1
                # jmp addr0
                
                jmp_code = "jc {addr1}; jnp {addr1}; jmp {addr0}"
            elif cont_mode in [0x50, 0x57, 0x5C, 0x6E]:
                # CF != 0 -> Addr1 else Addr0
                # jnc addr0
                # jmp addr1
                
                jmp_code = "jnc {addr0}; jmp {addr1}"
            else:
                pass
                # jmp addr0
                
                jmp_code = "jmp {addr0}"
            
            # print(hex(addr), hex(addr0), hex(addr1))
            block_offset0 = addr0 - nearest_block(addr0)
            block_offset1 = addr1 - nearest_block(addr1)
            
            addr0_index = visited_blocks.index(addr0 - block_offset0)
            addr1_index = visited_blocks.index(addr1 - block_offset1)
            
            # print(addr0_index, addr1_index)
            
            addr0_jmptarg = block_offset0 + sum(block_sizes[:addr0_index]) + 16 * addr0_index - len(code_out)
            addr1_jmptarg = block_offset1 + sum(block_sizes[:addr1_index]) + 16 * addr1_index - len(code_out)
            
            jmp_code = jmp_code.format(addr0=addr0_jmptarg, addr1=addr1_jmptarg)
            jmp_code_bin = assemble(jmp_code)
            # print(hex(addr), hex(addr0), hex(addr1), hex(cont_mode), hex(unk3))
            jmp_code_bin += b"\x90" * (16 - len(jmp_code_bin))
            code_out += jmp_code_bin
            
            next_block = min(addr0 - block_offset0, addr1 - block_offset1)
            if next_block == addr:
                next_block = max(addr0 - block_offset0, addr1 - block_offset1)
            
            i = obfu_code_table[next_block][0]

    if print_code:
        for instr in md.disasm(code_out, start_offset):
            print(instr)
    
    """
    with open("bins/" + hex(ecstart) + ".bin", "wb") as f:
        f.write(code_out)
    """
    
    return code_out

def get_all_stubs():
    pe_data = ql.mem.read(image_start, image_size)
    f = open("func_table.txt", "w")
    
    obfu_jmps = []
    bad_stubs = []
    
    # "nooo write another function dont just copy paste a loop twice" :nerd:
    for match in re.finditer(STUB_RET4_REGEX, pe_data):
        match_addr = image_start + match.start()
        # print(hex(match_addr))
        stub_code = ql.mem.read(match_addr - 0x50, 0x50)
        
        try:
            stub_start_offset = list(re.finditer(PUSH_REGEX, stub_code, re.DOTALL))[0].start()
        except:
            # print("A")
            continue
        
        stub_start_addr = match_addr - 0x50 + stub_start_offset
        instrs = list(md.disasm(ql.mem.read(stub_start_addr, 0x47), stub_start_addr))
        ret = 0
        
        for i, instr in enumerate(instrs):
            # print(instr)
            
            if instr.mnemonic == "ret" and instr.op_str == "4":
                ret = i
                break
        
        if ret < 8:
            # print("B")
            continue
        
        # min 7 backwards -> first push instr, then stop
        # much better than whatever this is supposed to be
        
        stub_start_index = ret - 8
        
        if instrs[ret-2].mnemonic == "mov":
            stub_start_index -= 1
        
        if instrs[stub_start_index].mnemonic == "mov" or instrs[stub_start_index].mnemonic == "push":
            stub_start_index += 1
        elif instrs[stub_start_index].mnemonic != "lea":
            # print("C")
            continue
        
        stub_start = instrs[stub_start_index].address
        
        try:
            used_reg = list(md.disasm(instrs[stub_start_index].bytes, 0))[0].operands[0].value.reg
        except:
            raise Exception("D")
        
        if used_reg not in REG_NAMES:
            # print("E")
            continue
        
        used_reg_name = REG_NAMES[used_reg].lower()
        
        # print("ADDRESS ASSIGNED @ " + hex(stub_start))
        
        len_stub = (instrs[ret].address + 3) - stub_start
        # ql.mem.write(stub_start, NOP * len_stub)
        # ql.mem.write(chksum_data, NOP * 16)

        push_instrs = list(map(lambda c: bytearray(ks.asm(c)[0]), [f"push {used_reg_name}", f"lea esp, [esp-4]", f"mov [esp], {used_reg_name}"]))
        jmp_insert_addr = 0
        
        for inst in instrs[max(0,stub_start_index-4):stub_start_index][::-1]:
            # print(inst)
            if inst.bytes in push_instrs:
                # ql.mem.write(inst.address, NOP * len(inst.bytes))
                jmp_insert_addr = inst.address
            else:
                break
        
        if jmp_insert_addr == 0:
            # print("F")
            continue
        
        # print("NOPPED STARTING @ " + hex(jmp_insert_addr))
        
        print("PASS1")
        
        try:
            ql.run(begin=jmp_insert_addr, end=instrs[ret].address)
            
            handler_addr = ql.arch.stack_pop()
            ql.arch.stack_pop()
            next_addr = ql.arch.stack_pop()
        except:
            handler_addr = -1
            next_addr = -1
        
        if handler_addr == 0 or next_addr == 0  or handler_addr == -1 or next_addr == -1:
            bad_stubs.append(jmp_insert_addr)
            continue
        
        print("PASS2")
        
        # print("HANDLER @ " + hex(handler_addr))
        # print("JUMP TARGET @ " + hex(next_addr))
        # print(ql.arch.regs.esp)
        
        if handler_addr in sym_data:
            handler_name = sym_data[handler_addr]
        else:
            handler_name = hex(handler_addr)
        
        if next_addr in sym_data:
            next_name = f"{hex(next_addr)} {sym_data[next_addr]}"
        else:
            next_name = hex(next_addr)
        
        jmp_end_addr = instrs[ret].address + instrs[ret].size
        obfu_jmps.append((jmp_insert_addr, jmp_end_addr, handler_addr, next_addr))
        
        f.write(f"J R4 S {hex(jmp_insert_addr)} H {handler_name} N {next_name}\n")
        
        # input()
        # print()
        # input()
    
    for match in re.finditer(STUB_RET0_REGEX, pe_data):
        match_addr = image_start + match.start()
        # print(hex(match_addr))
        stub_code = ql.mem.read(match_addr - 0x30, 0x30)
        
        try:
            stub_start_offset = list(re.finditer(PUSH_REGEX, stub_code, re.DOTALL))[0].start()
        except:
            # print("A")
            continue
        
        stub_start_addr = match_addr - 0x30 + stub_start_offset
        instrs = list(md.disasm(ql.mem.read(stub_start_addr, 0x47), stub_start_addr))
        ret = 0
        
        for i, instr in enumerate(instrs):
            # print(instr)
            
            if instr.mnemonic == "ret" and instr.op_str == "":
                ret = i
                break
        
        if ret < 7:
            # print("A2", ret)
            continue
        
        # min 7 backwards -> first push instr, then stop
        # much better than whatever this is supposed to be
        
        stub_start_index = ret - 7
        
        if instrs[ret-2].mnemonic == "mov":
            stub_start_index -= 1
        
        if instrs[stub_start_index].mnemonic == "mov" or instrs[stub_start_index].mnemonic == "push":
            stub_start_index += 1
        elif instrs[stub_start_index].mnemonic != "lea":
            # print("B")
            continue
        
        stub_start = instrs[stub_start_index].address
        
        try:
            used_reg = list(md.disasm(instrs[stub_start_index].bytes, 0))[0].operands[0].value.reg
        except:
            raise Exception("C")
        
        if used_reg not in REG_NAMES:
            # print("D")
            continue
        
        used_reg_name = REG_NAMES[used_reg].lower()
        
        # print("ADDRESS ASSIGNED @ " + hex(stub_start))
        
        len_stub = (instrs[ret].address + 3) - stub_start
        # ql.mem.write(stub_start, NOP * len_stub)
        # ql.mem.write(chksum_data, NOP * 16)

        push_instrs = list(map(lambda c: bytearray(ks.asm(c)[0]), [f"push {used_reg_name}", f"lea esp, [esp-4]", f"mov [esp], {used_reg_name}"]))
        jmp_insert_addr = 0
        
        for inst in instrs[max(0,stub_start_index-4):stub_start_index][::-1]:
            # print(inst)
            if inst.bytes in push_instrs:
                # ql.mem.write(inst.address, NOP * len(inst.bytes))
                jmp_insert_addr = inst.address
            else:
                break
        
        if jmp_insert_addr == 0:
            # print("E")
            continue
        
        # print("NOPPED STARTING @ " + hex(jmp_insert_addr))
        
        try:
            ql.run(begin=jmp_insert_addr, end=instrs[ret].address)
            
            handler_addr = ql.arch.stack_pop()
            next_addr = ql.arch.stack_pop()
        except:
            handler_addr = -1
            next_addr = -1
        
        if handler_addr == 0 or next_addr == 0 or handler_addr == -1 or next_addr == -1:
            bad_stubs.append(jmp_insert_addr)
            continue
        
        # print("HANDLER @ " + hex(handler_addr))
        # print("JUMP TARGET @ " + hex(next_addr))
        # print(ql.arch.regs.esp)
        
        if handler_addr in sym_data:
            handler_name = sym_data[handler_addr]
        else:
            handler_name = hex(handler_addr)
        
        if next_addr in sym_data:
            next_name = f"{hex(next_addr)} {sym_data[next_addr]}"
        else:
            next_name = hex(next_addr)
        
        jmp_end_addr = instrs[ret].address + instrs[ret].size
        obfu_jmps.append((jmp_insert_addr, jmp_end_addr, handler_addr, next_addr))
        
        f.write(f"J R0 S {hex(jmp_insert_addr)} H {handler_name} N {next_name}\n")
        
        # input()
        # print()
        # input()
    
    f.close()
    
    return obfu_jmps, bad_stubs

def add_pe_section(pe, name, characteristics=0x60000020, size=0x100000):
    f_align = pe.OPTIONAL_HEADER.FileAlignment
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    
    if len(name) > 8:
        raise Exception("Section name too long!")
    
    data = b"\x00" * size
    if size % f_align == 0:
        data += b"\x00" * (f_align - (len(data) % f_align))
    
    sect_table_offset = pe.DOS_HEADER.e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
    sect_table_end_offset = sect_table_offset + pe.FILE_HEADER.NumberOfSections * 0x28
    
    if pe.OPTIONAL_HEADER.SizeOfHeaders - sect_table_end_offset < 0x28:
        raise Exception("Not enough space for header")
    
    raw_addr = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
    virt_addr = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
    
    if virt_addr % sect_align != 0:
        virt_addr += sect_align - (virt_addr % sect_align)
    
    pe.__data__ = pe.__data__[:raw_addr] + data + pe.__data__[raw_addr:]
    
    sect_header = struct.pack("<8sIIIIIIII", name.encode("utf-8"), len(data), virt_addr, len(data), raw_addr, 0, 0, 0, characteristics)
    pe.set_bytes_at_offset(sect_table_end_offset, sect_header)
    
    pe.FILE_HEADER.NumberOfSections += 1
    pe.parse_sections(sect_table_offset)
    
    pe.OPTIONAL_HEADER.SizeOfImage = pe.sections[-1].VirtualAddress + pe.sections[-1].Misc_VirtualSize
    pe.OPTIONAL_HEADER.SizeOfCode = 0
    pe.OPTIONAL_HEADER.SizeOfInitializedData = 0
    pe.OPTIONAL_HEADER.SizeOfUninitializedData = 0
    
    for sect in pe.sections:
        if sect.Characteristics & 0x20 != 0:
            pe.OPTIONAL_HEADER.SizeOfCode += sect.SizeOfRawData
        if sect.Characteristics & 0x40 != 0:
            pe.OPTIONAL_HEADER.SizeOfInitializedData += sect.SizeOfRawData
        if sect.Characteristics & 0x80 != 0:
            pe.OPTIONAL_HEADER.SizeOfUninitializedData += sect.SizeOfRawData

if __name__ == "__main__":
    print("peacestone copyleft UMSKT project 2023")
    print()
    
    # os.makedirs("bins", exist_ok=True)
    
    #"""
    print("Finding all obfuscated jump stubs...")
    obfu_jmps, bad_stubs = get_all_stubs()
    
    print(f"Found {len(obfu_jmps)} stubs.")
    
    if len(bad_stubs) > 0:
        print(f"WARNING: Found {len(bad_stubs)} stubs that could not be automatically deobfuscated.")
    
    encr_funcs = []
    
    for addr in obfu_code_table:
        if addr in sym_data:
            encr_funcs.append(addr)
    
    print(f"Found {len(encr_funcs)} named encrypted functions.")
    
    print()
    print("Deobfuscating...")
    
    pe = pefile.PE(BIN_NAME)
    add_pe_section(pe, ".pstone")
    
    deobf_cur = pe.sections[-1].VirtualAddress
    deobf_table = {}
    
    for func in encr_funcs:
        df_code = deobfu_func(func, image_start + deobf_cur)
        pe.set_bytes_at_rva(deobf_cur, df_code)
        
        ecstart_replace_code = assemble(f"jmp {image_start + deobf_cur - func}")
        pe.set_bytes_at_rva(func - image_start, ecstart_replace_code)
        
        deobf_table[func] = deobf_cur
        
        deobf_cur += len(df_code)
    
    obfu_handler = sym_data_inv["?Stub_EnterObfuscatedMode@WARBIRD@@YAXXZ"]
    verify_handler = sym_data_inv["?Stub_VerifyVerifierCheckSum@WARBIRD@@YAXXZ"]
    
    for start, end, handler, arg in obfu_jmps:
        # print(hex(start), hex(end), hex(handler), hex(arg))
        if handler == obfu_handler:
            # print("^OBFU")
            if arg in deobf_table:
                deobf_offset = deobf_table[arg]
            else:
                deobf_offset = deobf_cur
                
                df_code = deobfu_func(arg, image_start + deobf_cur)
                pe.set_bytes_at_rva(deobf_cur, df_code)
                
                ecstart_replace_code = assemble(f"jmp {image_start + deobf_offset - arg}")
                pe.set_bytes_at_rva(arg - image_start, ecstart_replace_code)
                
                deobf_table[arg] = deobf_cur
                
                deobf_cur += len(df_code)
                
            stub_replace_code = assemble(f"jmp {image_start + deobf_offset - start}")
            stub_replace_code += b"\x90" * (end - start - len(stub_replace_code))
        elif handler == verify_handler:
            # print("^VERIFY")
            stub_replace_code = assemble(f"jmp {arg + 0x10 - start}")
            stub_replace_code += b"\x90" * (end - start - len(stub_replace_code)) + b"\x90" * 16
        else:
            # print("^NEITHER")
            stub_replace_code = assemble(f"call {handler - start}")
            stub_replace_code += b"\x90" * (end - start - len(stub_replace_code))
        
        pe.set_bytes_at_rva(start - image_start, stub_replace_code)
    #"""
    
    md.detail = False
    
    print("Removing thunk indirection...")
    
    func_addrs = sym_addrs + sorted(map(lambda a: a + image_start, deobf_table.values()))
    
    for i, func in enumerate(func_addrs):
        # All MSVC-compiled functions start with mov edi, edi (8B FF)
        
        if pe.get_data(func - image_start, 2) == b"\x8b\xff":
            # print(hex(func))
            
            if i < len(func_addrs) - 1:
                read_len = func_addrs[i+1] - func
            else:
                read_len = 0x10000
            
            for instr in md.disasm(pe.get_data(func - image_start, read_len), func):
                # print(instr)
                
                if instr.mnemonic == "call":
                    # print("CALL")
                    try:
                        # print("VALID")
                        jmp_target = int(instr.op_str, 16)
                        target_instr = next(md.disasm(ql.mem.read(jmp_target, 16), jmp_target))
                        # print(target_instr)
                        
                        if target_instr.mnemonic == "jmp":
                            # print("PATCH")
                            true_target = int(target_instr.op_str, 16)
                            replace_call = assemble(f"call {true_target - instr.address}")
                            pe.set_bytes_at_rva(instr.address - image_start, replace_call)
                    except:
                        continue
    
    if BIN_NAME[-4:] == ".dll":
        orig_main = sym_data_inv["__DllMainCRTStartup@12"]
    else:
        orig_main = sym_data_inv["_wmainCRTStartup"]
    
    print("Patching entry point...")
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = orig_main - image_start
    
    print("Done! Saving.")
    
    pe.write(BIN_NAME.replace(".exe", ".stoned.exe").replace(".dll", ".stoned.dll"))