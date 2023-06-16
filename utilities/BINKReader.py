import tkinter as tk
import os

from colorama import init as colorama_init, Fore, Back, Style
from datetime import datetime as dt
from tkinter import filedialog


class TermColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def file_picker():
    print(f"{Style.BRIGHT}Please select a BINK resource file.{Style.RESET_ALL}")

    path = filedialog.askopenfilename(
        parent=None,
        title="Select a file",
        filetypes=(("BINK resources", "*.bin"), ("All files", "*.*"))
    )

    if not path:
        print(f"{Fore.RED}{Style.BRIGHT}Error: No file selected.{Style.RESET_ALL}")
        exit(1)

    print(f"{Fore.LIGHTBLUE_EX}Loading file {path}...{Style.RESET_ALL}\n")
    return path


def output_raw(bink_data, granularity=16):
    byte_str = bink_data.hex(sep=' ', bytes_per_sep=1).upper()
    p = list(map(''.join, zip(*[iter(byte_str)] * (granularity * 3))))

    for i in range(len(p)):
        p[i] = f"{Fore.GREEN}{Style.BRIGHT}0x{i * granularity:04X}{Style.RESET_ALL}: {p[i]}\n"

    print(f"{Fore.MAGENTA}{Style.BRIGHT}Raw BINK data:{Style.RESET_ALL}\n{''.join(p)}{Fore.YELLOW}--EOF--{Style.RESET_ALL} ({len(bink_data)} bytes)\n")


def validate_header(bink_header, bink_length):
    sizeof = int.from_bytes(bink_header[0x04:0x08], byteorder='little')
    countof = int.from_bytes(bink_header[0x08:0x0C], byteorder='little')

    # Windows XP - sizeof(BINKEY) == 0x016C && countof(BINKHDR) == 0x07
    # Windows Server 2003 - sizeof(BINKEY) == 0x01E4 && countof(BINKHDR) == 0x09
    if sizeof + 0x04 == bink_length and sizeof == 0x016C and countof == 0x07 or sizeof == 0x01E4 and countof == 0x09:
        return True

    return False


def decode(bink_data):
    bink_header = bink_data[:0x20]
    bink_values = bink_data[0x20:]

    if not validate_header(bink_header, len(bink_data)):
        print(f"{Fore.RED}{Style.BRIGHT}Error: Invalid BINK file.{Style.RESET_ALL}")
        return

    output_raw(bink_data)

    identifier = int.from_bytes(bink_header[0x00:0x04], byteorder='little')
    sizeof = int.from_bytes(bink_header[0x04:0x08], byteorder='little')
    countof = int.from_bytes(bink_header[0x08:0x0C], byteorder='little')
    checksum = int.from_bytes(bink_header[0x0C:0x10], byteorder='little')
    version = int.from_bytes(bink_header[0x10:0x14], byteorder='little')
    keysize = int.from_bytes(bink_header[0x14:0x18], byteorder='little')
    hashlen = int.from_bytes(bink_header[0x18:0x1C], byteorder='little')
    siglen = int.from_bytes(bink_header[0x1C:0x20], byteorder='little')

    server = countof == 0x09

    print(f"{Fore.MAGENTA}{Style.BRIGHT}BINK header:{Style.RESET_ALL}")

    print(f"{Fore.LIGHTYELLOW_EX}Operating System:{Style.RESET_ALL}\t{'Windows Server 2003 / XP SP2 x64' if server else 'Windows 98 / XP x86'}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}Identifier:{Style.RESET_ALL}\t\t\t0x{identifier:04X}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}sizeof(BINKEY):{Style.RESET_ALL}\t\t{sizeof}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}Header Length:{Style.RESET_ALL}\t\t{countof}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}Checksum:{Style.RESET_ALL}\t\t\t0x{checksum:08X} ({checksum}){Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}Creation Date:{Style.RESET_ALL}\t\t{dt(version // 10000, version // 100 % 100, version % 100, 0, 0)}{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}ECC Key Size:{Style.RESET_ALL}\t\t{keysize * 4 * 8} bits ({keysize} DWORDs){Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}Hash Length:{Style.RESET_ALL}\t\t{hashlen} bits{Style.RESET_ALL}")
    print(f"{Fore.LIGHTYELLOW_EX}Signature Length:{Style.RESET_ALL}\t{siglen} bits{Style.RESET_ALL}\n")

    # Windows Server 2003 uses an extended header format, meaning the content segment size and offset are different.
    if server:
        bink_header = bink_data[:0x28]
        bink_values = bink_data[0x28:]

        authlen = int.from_bytes(bink_header[0x20:0x24], byteorder='little')
        pidlen = int.from_bytes(bink_header[0x24:0x28], byteorder='little')

        print(f"{Fore.LIGHTYELLOW_EX}Auth Field Length:{Style.RESET_ALL}\t{authlen} bits{Style.RESET_ALL}")
        print(f"{Fore.LIGHTYELLOW_EX}Product ID Length:{Style.RESET_ALL}\t{pidlen} bits{Style.RESET_ALL}\n")

    curve_params = {
        'p': 'Finite Field Order',
        'a': 'Curve Parameter',
        'b': 'Curve Parameter',
        'Gx': 'Base Point x-coordinate',
        'Gy': 'Base Point y-coordinate',
        'Kx': 'Public Key x-coordinate',
        'Ky': 'Public Key y-coordinate',
    }

    print(f"{Fore.MAGENTA}{Style.BRIGHT}BINK Elliptic Curve Parameters:{Style.RESET_ALL}")

    offset = keysize * 4

    for i, (x, y) in enumerate(curve_params.items()):
        param = int.from_bytes(bink_values[i * offset:(i + 1) * offset], byteorder='little')
        print(f"{Fore.LIGHTCYAN_EX}{y} {x}:{Style.RESET_ALL}\nHex: 0x{param:02X}\nDec: {param}{Style.RESET_ALL}\n")


def main():
    root = tk.Tk()
    root.withdraw()

    print(f"{Style.BRIGHT}BINK Reader v1.0 by {Fore.MAGENTA}Endermanch{Style.RESET_ALL}\n")

    bink_path = file_picker()

    try:
        with open(bink_path, "rb") as f:
            decode(f.read())

    except EnvironmentError:
        print(f"{Fore.RED}{Style.BRIGHT}Error: Could not open BINK file.{Style.RESET_ALL}")


if __name__ == "__main__":
    os.system('color')
    main()

