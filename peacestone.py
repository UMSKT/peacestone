from qiling import *
from qiling.const import *
from capstone import *
from keystone import *
import json

# Set to binary name
BIN_NAME = "sppsvc.exe"

# Set to function to be analyzed
ANLZ_FUNC = "?VerifyPKeyByInstalledPidConfig@CSLSLicenseManager@@IBEJPAVCSLPKey@@PBGPAUtagPKEY_BASIC_INFO@@PAPAGPAUDECODED_PKEY_DATA@@@Z"

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
ql = Qiling(["./rootfs/sppsvc.exe"], "./rootfs")

def func_boundary(fun_name):
    f_start = sym_data_inv[ANLZ_FUNC]
    ind = sym_addrs.index(f_start)
    f_end = sym_addrs[ind+1]
    
    return f_start, f_end

def save_patched_exe():
    for region in ql.mem.get_mapinfo():
        if region[3] == BIN_NAME:
            exe_start = region[0]
            exe_end = region[1]
    
    with open(BIN_NAME.replace(".exe", ".stoned.exe"), "wb") as f:
        f.write(ql.mem.read(exe_start, exe_end - exe_start))

def remove_verify_stubs():
    global ql
    
    f_start, f_end = func_boundary(ANLZ_FUNC)
    f_start_orig = f_start
    orig_ql_state = ql.save()
    offset = 0

    while f_start < f_end:
        stop = False
        f_code = ql.mem.read(f_start, f_end - f_start)
        instrs = list(md.disasm(f_code, f_start))

        print("INSTRS @ " + hex(f_start))
        
        for i in instrs:
            print(i)

        ret = 0
        for i, inst in enumerate(instrs):
            if inst.mnemonic == "ret" and inst.op_str == "4":
                ret = i
                break
        
        if ret < 8:
            stop = True

        stub_start_index = ret - 8
        
        if instrs[stub_start_index].mnemonic == "mov" or instrs[stub_start_index].mnemonic == "push":
            stub_start_index = ret - 7
        elif instrs[stub_start_index].mnemonic != "lea":
            stop = True
        
        stub_start = instrs[stub_start_index].address
        
        try:
            used_reg = list(md.disasm(instrs[stub_start_index].bytes, 0))[0].operands[0].value.reg
        except:
            stop = True
        
        used_reg_name = REG_NAMES[used_reg].lower()
        
        if stop:
            print("VERIFY STUB REMOVAL FINISHED")
            break
        
        print("ADDRESS ASSIGNED @ " + hex(stub_start))
        
        ql.run(begin=stub_start, end=instrs[stub_start_index+2].address)
        chksum_data = ql.arch.regs.read(used_reg)

        print("CHKSUM @ " + hex(chksum_data))
        
        len_stub = (instrs[ret].address + 3) - stub_start
        ql.mem.write(stub_start, NOP * len_stub)
        ql.mem.write(chksum_data, NOP * 16)

        push_instrs = list(map(lambda c: bytearray(ks.asm(c)[0]), [f"push {used_reg_name}", f"lea esp, [esp-4]", f"mov [esp], {used_reg_name}"]))
        jmp_insert_addr = 0
        
        for inst in instrs[max(0,stub_start_index-4):stub_start_index][::-1]:
            if inst.bytes in push_instrs:
                ql.mem.write(inst.address, NOP * len(inst.bytes))
                jmp_insert_addr = inst.address
            else:
                break
        
        f_start = chksum_data + 0x10
        
        print("NOPPED STARTING @ " + hex(jmp_insert_addr))
        print("NEXT: " + hex(f_start + offset))

if __name__ == "__main__":
    print("peacestone copyleft UMSKT project 2023")
    print()
    
    remove_verify_stubs()
    save_patched_exe()