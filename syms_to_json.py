import re
import json

# llvm-pdbutil pretty -externals sppsvc.pdb -load-address=0x01000000 > syms.txt

with open("syms.txt", "r") as f:
    text = f.read()
    symdata = re.findall(r" public \[(\w+)\] (\S+)", text, re.MULTILINE)
    
    addrs = []
    unique_syms = []
    
    for addr, sym in symdata:
        if addr not in addrs:
            unique_syms.append((addr, sym))
            addrs.append(addr)
    
    unique_syms = dict(unique_syms)
    
    with open("syms.json", "w") as g:
        g.write(json.dumps(unique_syms, indent=4))