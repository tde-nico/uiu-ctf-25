import ida_hexrays
import ida_lines
import ida_funcs
import ida_kernwin
import idautils
import idc
import idaapi
import ida_ua

import re


ea = idaapi.get_screen_ea()
func = ida_funcs.get_func(ea)

if not func:
	print("No function found at the current address.")
	exit(1)

start = func.start_ea
end = func.end_ea

sd_codes = {
	0: 'exit',
    105: 'print a4',
    719: 'push_call_1',
    720: 'push_call_2',
    721: 'push_call_3',
    1195: 'push a4',
    1401: 'stack[-1] |= a4',
    1763: 'stack[-1] ^= a4',
    3094: 'stack[-1] *= a4',
    3291: 'stack[-1] rol= a4',
    3625: 'encrypt a4',
    3893: 'stack[-1] += a4'
}

ld_codes = {
	0: 'exit',
    105: 'getchar a4',
    719: 'pop_call_1',
    720: 'pop_call_2',
    721: 'pop_call_3',
    1195: 'pop a4',
    1401: 'a4 = stack[-2] | stack[-1]',
    1763: 'a4 = stack[-2] ^ stack[-1]',
    3094: 'a4 = stack[-2] * stack[-1]',
    3291: 'a4 = rol stack[-2] stack[-1]',
    3625: 'decrypt a4',
    3893: 'a4 = stack[-2] + stack[-1]'
}

def decode_vm_opcode(stval):
    return (105 * (stval ^ 0x420)) & 0xFFF

blacklist = [
	# 0x80100350,
]

li_regex = re.compile(r"li\s*a(.),\s(.*)h")
sd_regex = re.compile(r"s(d|b)\s*(a4|zero),\s0\(a(.)\)")
ld_regex = re.compile(r"l(d|bu)\s*a.,\s0\(a(.)\)")
lui = 'lui             a5, 1'
addi_regex = re.compile(r"addi\s*a.,\sa.,\s(.*)h")

PRINT = 1

insts = []
a4 = None
a5 = None

addr = start
while addr < end:
	inst = idc.GetDisasm(addr)
	insn = ida_ua.insn_t()
	ida_ua.decode_insn(insn, addr)
	inst_size = insn.size

	if addr not in blacklist:
		if m := li_regex.match(inst):
			if int(m.group(1)) == 4:
				if a4 is not None:
					print(f"Warning: Found 'li a4' instruction at {hex(addr)} while already processing a call.")
					break
				a4 = int(m.group(2), 16)
			else:
				if a5 is not None:
					print(f"Warning: Found 'li a5' instruction at {hex(addr)} while already processing a call.")
					break
				a5 = int(m.group(2), 16)
			addr += inst_size
			continue

		elif m := sd_regex.match(inst):
			if int(m.group(3)) == 4:
				if a4 is None:
					print(f"Warning: Found 'sd a4' without a preceding 'li' instruction at {hex(addr)}")
					break
				real_func = decode_vm_opcode(a4)
				real_func = sd_codes.get(real_func, f'unknown_{real_func}')
				a4 = None
			else:
				if a5 is None:
					print(f"Warning: Found 'sd a5' without a preceding 'li' instruction at {hex(addr)}")
					break
				real_func = decode_vm_opcode(a5)
				real_func = sd_codes.get(real_func, f'unknown_{real_func}')
				a5 = None
			inst = f'{real_func}'

		elif m := ld_regex.match(inst):
			if int(m.group(2)) == 4:
				if a4 is None:
					print(f"Warning: Found 'ld a4' without a preceding 'li' instruction at {hex(addr)}")
					break
				real_func = decode_vm_opcode(a4)
				real_func = ld_codes.get(real_func, f'unknown_{real_func}')
				a4 = None
			else:
				if a5 is None:
					print(f"Warning: Found 'ld a5' without a preceding 'li' instruction at {hex(addr)}")
					break
				real_func = decode_vm_opcode(a5)
				real_func = ld_codes.get(real_func, f'unknown_{real_func}')
				a5 = None
			inst = f'{real_func}'
		
		elif lui in inst:
			addi_inst = idc.GetDisasm(addr+inst_size)
			addi_insn = ida_ua.insn_t()
			ida_ua.decode_insn(addi_insn, addr+inst_size)
			inst_size += addi_insn.size

			m = addi_regex.match(addi_inst)
			a4 = int(m.group(1), 16)
			
			addr += inst_size
			continue



	insts.append((addr, inst))
	if PRINT:
		print(f"{hex(addr)}: {inst}")

	addr += inst_size

else:
	with open('decomp.txt', 'w') as f:
		for addr, inst in insts:
			f.write(f"loc_{hex(addr)[2:]}: {inst}\n")
			if inst.startswith('j') or inst.startswith('exit') or inst.startswith('b'):
				f.write("\n\n")
