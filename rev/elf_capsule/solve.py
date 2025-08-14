from z3 import *


def flag_to_data(flag):
    memory_data = [
        0x70, 0x17, 0x58, 0x61, 0x76, 0x01, 0x00, 0x4e,
        0x45, 0xc7, 0xdf, 0xa9, 0xc2, 0xa3, 0x2a, 0xd6,
        0xf2, 0x3a, 0xca, 0x49, 0x39, 0xc0, 0xdb, 0x03,
        0x70, 0x72, 0x71, 0xea, 0x5f, 0xaa, 0xb7, 0x48,
        0x3a, 0xa1, 0x9b, 0x4e, 0x21, 0x3c, 0xa3, 0x39,
        0xbf, 0x15, 0x16, 0x81, 0x0a, 0xc7, 0xba, 0xfb,
        0x27, 0x50, 0x95, 0x39, 0xea, 0x7d, 0x6b, 0xc5,
        0x89, 0x03, 0x98, 0xbf, 0xf0, 0xd7, 0x99, 0xdb,
        0x30, 0x7c, 0xd7, 0x7a, 0x4b, 0xbf, 0xe1, 0x5e,
        0xb4, 0xb0, 0xc9, 0xc4, 0x31, 0xb6, 0x10, 0x5c,
        0x7f, 0xe6, 0xbc, 0x64, 0x9e, 0xdc, 0xe4, 0x89,
        0xc3, 0x5e, 0x1b, 0xcd, 0x01, 0x71, 0x29, 0x9d,
        0x6a, 0x8d, 0xed, 0x52, 0x33, 0xc2, 0x71, 0x02,
        0x46, 0x46, 0x0d, 0xc7, 0xe1, 0xde, 0x6c, 0xe1,
        0xef, 0xbb, 0x7f, 0x7b, 0x9c, 0xb7, 0x39, 0x1d,
        0x70, 0xeb, 0x02, 0x32, 0xe6, 0x61, 0x03, 0xdf,
    ]

    memory = memory_data[::] + [0] * 100

    buf_1 = 0x800060A0 - 0x800060A0
    buf_2 = 0x800060DF - 0x800060A0
    buf_3 = 0x800060E0 - 0x800060A0
    buf_4 = 0x8000611F - 0x800060A0

    for b in flag:
        b = (b ^ 0xff) + 1
        memory[buf_1] = b ^ 0x29
        memory[buf_2] = b - 82
        memory[buf_3] = b ^ ((memory[buf_2] - memory[buf_1]) & 0xFF)
        v71 = ((b & 0xFF) << 4) | ((b & 0xFF) >> 4)
        memory[buf_4] = v71 & 0xFF
        buf_1 += 1
        buf_2 -= 1
        buf_3 += 1
        buf_4 -= 1

    qwords = []
    for addr in range(0, 128, 16):
        bytes_data = []
        for i in range(16):
            bytes_data.append(memory[addr + i])

        qword1 = 0
        qword2 = 0
        for i in range(8):
            qword1 |= (bytes_data[i] << (i * 8))
            qword2 |= (bytes_data[i + 8] << (i * 8))

        qwords.append(qword1)
        qwords.append(qword2)

    return qwords


def rot_l(x, n):
    n %= 64
    x = ((x << n) | (x >> (64-n)) & 0xFFFFFFFFFFFFFFFF)
    return x & 0xFFFFFFFFFFFFFFFF


def crc1(data):
    for i in range(1, 8):
        data[-i] = rot_l(data[-i], i ** 2) ^ 0x9E3779B97F4A7C15

        local_60 = data[-i]
        local_68 = data[-i - 1]

        data[-i - 1] = ((((local_60 ^ local_68) + 3) & 0xFFFFFFFFFFFFFFFF) +
                        ((((local_60 ^ 0xFFFFFFFFFFFFFFFF) | (
                                    local_68 ^ 0xFFFFFFFFFFFFFFFF)) * 3) & 0xFFFFFFFFFFFFFFFF) +
                        ((((local_60 ^ 0xFFFFFFFFFFFFFFFF) | (
                                    local_68 ^ 0xFFFFFFFFFFFFFFFF)) ^ 0xFFFFFFFFFFFFFFFF) * 5) & 0xFFFFFFFFFFFFFFFF)

        data[-i - 1] &= 0xFFFFFFFFFFFFFFFF

    return data[0]


def crc2(data):
    i = 8

    for _ in range(5):
        data[-1] = rot_l(data[-1], i ** 2) ^ 0x9E3779B97F4A7C15
        i += 1

        local_60 = data[-1]
        local_68 = data[-2]
        data = data[:-2]

        data.append((local_68 ^ 0xFFFFFFFFFFFFFFFF) + 1 + local_60)
        data[-1] &= 0xFFFFFFFFFFFFFFFF

    s.add(data[-1] == 0x0796DCF410F11057)

    for _ in range(2):
        data[-1] = rot_l(data[-1], i ** 2) ^ 0x9E3779B97F4A7C15
        i += 1

        local_60 = data[-1]
        local_68 = data[-2]
        data = data[:-2]

        data.append((local_68 ^ 0xFFFFFFFFFFFFFFFF) + 1 + local_60)
        data[-1] &= 0xFFFFFFFFFFFFFFFF

    return data


for length in range(10, 0x50, 1): # 32
    flag = [BitVec(f'flag_{i}', 64) for i in range(length)]
    s = Solver()

    for i in range(len(flag)):
        s.add(flag[i] >= 48, flag[i] <= 125)

    s.add(flag[0] == ord('u'))
    s.add(flag[1] == ord('i'))
    s.add(flag[2] == ord('u'))
    s.add(flag[3] == ord('c'))
    s.add(flag[4] == ord('t'))
    s.add(flag[5] == ord('f'))
    s.add(flag[6] == ord('{'))
    s.add(flag[-1] == ord('}'))

    original = flag_to_data(flag)

    s.add(crc1(original[8:]) == 0x37FBE21EAE04066A)

    data = crc2(original[:8])
    x = data.pop()
    s.add(x == 0x5F36D6201C352A7A)

    print('Checking...', length)
    res = s.check()
    if res == sat:
        model = s.model()
        print("Solution found:")
        result = [chr(model[flag[i]].as_long()) if str(model[flag[i]]) != "None" else '?' for i in range(length)]
        print(''.join(result))
    else:
        print(res)

# uiuctf{M3m0Ry_M4ppED_SysTEmca11}
