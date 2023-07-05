import math


def count(b):
    p = 0

    for i in range(25):
        p += pow(24, 24 - i) * b[i]

    return p


if __name__ == '__main__':
    charset = "BCDFGHJKMPQRTVWXY2346789"
    key1 = "JCF8T-2MG8G-Q6BBK-MQKGT-X3GBB"
    key2 = "FFFFF-GGGGG-HHHHH-JJJJJ-KKKKK"
    key3 = "99999-99999-99999-99999-99999"

    b = []

    for x in key2:
        if x != '-':
            b.append(charset.index(x))

    result = count(b)

    print(f'Byte array: {b}; Length: {len(b)}\n{hex(result).upper()}')
    data = result.to_bytes(15, byteorder='little')

    hex_string = "".join("%02X " % b for b in data)
    print(hex_string)
