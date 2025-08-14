# microblazeel-buildroot-linux-uclibc-objdump -D blazing_fast > asm.txt
with open('asm.txt', 'r') as file:
	lines = file.readlines()

regs = [0] * 32
mem = [0] * (1024 * 1024 * 2)

MEM_OFFSET = 0x82000000

lines = lines[539:]

line_offset = len('800007f0:	b0008200 	')
idx = 0
for line in lines:
	line = line.strip()
	inst = line[line_offset:]
	op, *args = [i.replace(',', '') for i in inst.split() if i]
	if op == 'imm':
		imm = (int(args[0]) & 0xffff) << 16
	elif op == 'addik':
		rd = int(args[0][1:]) & 0xffff
		ra = int(args[1][1:]) & 0xffff
		imm2 = int(args[2]) & 0xffff
		if imm:
			imm2 |= imm
			imm = 0
		regs[rd] = regs[ra] + imm2
	elif op == 'swi':
		rd = int(args[0][1:]) & 0xffff
		ra = int(args[1][1:]) & 0xffff
		offset = int(args[2]) & 0xffff
		mem[(regs[ra] + offset - MEM_OFFSET) // 4] = regs[rd]
	else:
		print(f"Unknown operation at {idx}: {op}")
		break
	idx += 1

index = 0
for i, x in enumerate(mem):
	if x:
		index = i

from PIL import Image
rgb_bytes = bytearray()

mem = mem[:index+1]
lmao1 = mem[-(800 * 600):]
lmao2 = mem[:(800 * 600)]
for color in range(len(lmao1)):
	r1 = (lmao1[color] >> 16) & 0xFF
	g1 = (lmao1[color] >> 8) & 0xFF
	b1 = lmao1[color] & 0xFF
	r2 = (lmao2[color] >> 16) & 0xFF
	g2 = (lmao2[color] >> 8) & 0xFF
	b2 = lmao2[color] & 0xFF
	rgb_bytes.extend([r1|r2, g1|g2, b1|b2])

img = Image.frombytes("RGB", (800, 600), bytes(rgb_bytes))
img.show()
img.save("final.png")

# uiuctf{vdma_f0r_th3_w1n_xsuOrK|2BAIACt2}
