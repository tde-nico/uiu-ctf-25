f = [None] * 8

f[4] = int("35bf992d", 16)
f[5] = int("63ca828d", 16)
f[1] = int("7311d8a3", 16)
f[2] = int("78e51061", 16)
f[0] = int("7ed4d57b", 16)
f[3] = int("a6cecc1b", 16)
f[6] = int("c324c985", 16)
f[7] = int("c4647159", 16)
# f[2] = int("f8e50ff8", 16)


enc = [0x24189111, 0xFD94E945, 0x1B9F64A6, 0x7FECE9A3, 0xFC2A0EDE, 0x576EDCF5, 0x1E44C9C, 0x658AF790]

print('sigpwny{', end='')
for i in range(8):
	print(bytes.fromhex(hex(pow(enc[i], f[i], 0xFFFFFF2F))[2:])[::-1].decode(), end='')
print('}')


# sigpwny{CrackingDiscreteLogs4TheFun/Lols}
