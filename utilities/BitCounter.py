import math


def count_bits(number):
    return round(math.log2(number)) + 1


if __name__ == "__main__":
    number = int(input('Input a number: '))
    print(count_bits(number))

    number *= 2

    number_bytes = int.to_bytes(number, 49, byteorder='big')

    print(f"0x{number_bytes.hex().upper()}")