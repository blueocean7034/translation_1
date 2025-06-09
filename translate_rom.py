import os
from capstone import *

ROM_HEX_PATH = "my_rom_hex.txt"
OUTPUT_PATH = "assembly_output.txt"


def decode_rom():
    # Count total number of lines to get half of the ROM
    with open(ROM_HEX_PATH, 'r') as f:
        total_lines = sum(1 for _ in f)
    half_lines = total_lines // 2

    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN)
    md.detail = True

    address = 0
    with open(ROM_HEX_PATH, 'r') as f, open(OUTPUT_PATH, 'w') as out:
        for idx, line in enumerate(f):
            if idx >= half_lines:
                break
            line = line.strip()
            if not line:
                continue
            data = bytes.fromhex(line)
            for i in range(0, len(data), 4):
                word = data[i:i+4]
                for insn in md.disasm(word, address):
                    out.write(f"0x{address:08x}: {word.hex()}  {insn.mnemonic} {insn.op_str}\n")
                    for op_idx, op in enumerate(insn.operands):
                        if op.type == CS_OP_REG:
                            out.write(f"    operand[{op_idx}]: REG = {insn.reg_name(op.reg)}\n")
                        elif op.type == CS_OP_IMM:
                            out.write(f"    operand[{op_idx}]: IMM = {op.imm} (0x{op.imm & 0xffffffff:x})\n")
                        elif op.type == CS_OP_MEM:
                            base = insn.reg_name(op.mem.base) if op.mem.base else '0'
                            disp = op.mem.disp
                            out.write(f"    operand[{op_idx}]: MEM = base={base}, disp={disp} (0x{disp & 0xffffffff:x})\n")
                    out.write("\n")
                address += 4


def main():
    decode_rom()


if __name__ == "__main__":
    main()
