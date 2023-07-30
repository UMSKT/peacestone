#include <std/io.pat>

struct ObfBlockData {
    u32 u0;
    u32 u1;
    u32 u2;
    u32 u3;
    u32 u4;
};

ObfBlockData entries[0x323B] @ 0;

fn main() {
    u32 first = 0;
    u32 first_prev = 0;
    u32 last = 0x323A;
    u32 last_prev = 0x323A;
    u32 sum = 0;
    u32 stub_ret_offset = 0x20F989;
    u32 index = 0;
    u32 xor_value = 0;
    
    while (true) {
        index = (first + last) / 2;
        xor_value = entries[index].u0 ^ sum;
        
        if (stub_ret_offset >= xor_value) {
            if (stub_ret_offset >= xor_value + (entries[index].u3 & 0xFFF)) {
                first = index + 1;
                last = last_prev;
                first_prev = first;
                sum = entries[index].u0 - entries[index].u3;
                std::print("STAY {0:04X} >= {1:04X}\n", stub_ret_offset, xor_value + (entries[index].u3 & 0xFFF));
            } else {
                std::print("BREAK {0:04X} < {1:04X}\n", stub_ret_offset, xor_value + (entries[index].u3 & 0xFFF));
                std::print("INDEX {}\n", index);
                break;
            }
        } else {
            last = index - 1;
            last_prev = last;
            sum = entries[index].u0 + entries[index].u3;
        }
        
        if (last < first) {
            // set_handle_ret(handle_ret_addr);
            std::print("ERROR\n", xor_value);
            return;
        }
        
        std::print("XOR {0:04X}\n", xor_value);
        std::print("FIRST {0:04X}\n", first);
        std::print("LAST {0:04X}\n", last);
        std::print("SUM {0:04X}\n", sum);
    }
    
    u32 val1 = entries[index].u1 + entries[index].u0;
    u32 val2 = entries[index].u2 - entries[index].u0;
    u32 val3 = entries[index].u4 + entries[index].u3;
    std::print("VAL1 {0:04X}\n", val1);
    std::print("VAL2 {0:04X}\n", val2);
    std::print("VAL3 {0:04X}\n", val3);
};