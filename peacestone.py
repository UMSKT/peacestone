from qiling import *
from qiling.const import *
from capstone import *
from keystone import *
import pefile
import json
import re

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

def func_boundary(fun_name):
    f_start = sym_data_inv[ANLZ_FUNC]
    ind = sym_addrs.index(f_start)
    f_end = sym_addrs[ind+1]
    
    return f_start, f_end

def save_patched_exe():
    print("Fixing up sections...")
    with open(BIN_NAME.replace(".exe", ".stoned.exe"), "wb") as f:
        f.write(ql.mem.read(exe_start, exe_end - exe_start))

def assemble(instrs):
    return bytes(ks.asm(instrs)[0])

"""
def remove_verify_stubs():
    global ql
"""
    

if __name__ == "__main__":
    print("peacestone copyleft UMSKT project 2023")
    print()
    
    # remove_verify_stubs()
    # save_patched_exe()
    
    pe_data = ql.mem.read(image_start, image_size)
    f = open("log.txt", "w")
    
    for match in re.finditer(STUB_RET4_REGEX, pe_data):
        match_addr = image_start + match.start()
        stub_code = ql.mem.read(match_addr - 0x1000, 0x1000)
        
        try:
            stub_start_offset = list(re.finditer(PUSH_REGEX, stub_code))[0].start()
        except:
            continue
        
        stub_start_addr = match_addr - 0x1000 + stub_start_offset
        instrs = list(md.disasm(ql.mem.read(stub_start_addr, 0x47), stub_start_addr))
        ret = 0
        
        for i, instr in enumerate(instrs):
            # print(instr)
            
            if instr.mnemonic == "ret" and instr.op_str == "4":
                ret = i
                break
        
        if ret < 8:
            continue
        
        # min 7 backwards -> first push instr, then stop
        # much better than whatever this is supposed to be
        
        stub_start_index = ret - 8
        
        if instrs[ret-2].mnemonic == "mov":
            stub_start_index -= 1
        
        if instrs[stub_start_index].mnemonic == "mov" or instrs[stub_start_index].mnemonic == "push":
            stub_start_index += 1
        elif instrs[stub_start_index].mnemonic != "lea":
            print("CANT DEAL WITH THIS")
            continue
        
        stub_start = instrs[stub_start_index].address
        
        try:
            used_reg = list(md.disasm(instrs[stub_start_index].bytes, 0))[0].operands[0].value.reg
        except:
            raise Exception("CANT DEAL WITH THIS")
        
        if used_reg not in REG_NAMES:
            print("CANT DEAL WITH THIS")
            continue
        
        used_reg_name = REG_NAMES[used_reg].lower()
        
        print("ADDRESS ASSIGNED @ " + hex(stub_start))
        
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
            print("CANT DEAL WITH THIS")
            continue
        
        print("NOPPED STARTING @ " + hex(jmp_insert_addr))
        
        try:
            ql.run(begin=jmp_insert_addr, end=instrs[ret].address)
            
            handler_addr = ql.arch.stack_pop()
            ql.arch.stack_pop()
            next_addr = ql.arch.stack_pop()
        except:
            handler_addr = -1
            next_addr = -1
        
        print("HANDLER @ " + hex(handler_addr))
        print("JUMP TARGET @ " + hex(next_addr))
        print(ql.arch.regs.esp)
        
        if handler_addr in sym_data:
            handler_name = sym_data[handler_addr]
        else:
            handler_name = hex(handler_addr)
        
        f.write(f"J R4 S {hex(jmp_insert_addr)} H {handler_name} N {hex(next_addr)}\n")
        
        # input()
        print()