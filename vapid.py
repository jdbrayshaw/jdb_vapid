#!/usr/bin/env python3

#                              CREDITS
# Shared thoughts and worked in same session as Nick Arlinghaus. Got build.sh file directly from Edwin.

import os
import pefile
import re
import sys

filepath = sys.argv[1]
target_va = sys.argv[2].lower()

if os.path.isfile(filepath) == False or filepath.endswith(".exe") == False:
    print(f"File path {filepath} is not a valid file path. Please check input.")
    exit(1)

if target_va.startswith('0x'):
    addr_to_check = target_va[2:]
    hex_pattern = '^[0-9a-f]+$'
    if re.match(hex_pattern, addr_to_check).group() != addr_to_check:
        print(f"Target hex address {target_va} is not valid. Please check input.")
        exit(1)
    target_va = int(target_va, 16)         # converts hex string to dec for later math

else:
    decimal_pattern = '^[0-9]+$'
    if re.match(decimal_pattern, target_va).group() != target_va:
        print(f"Target decimal address {target_va} is not valid. Please check input.")
        exit(1)
    target_va = int(target_va)             # converts dec string to dec for later math

pe = pefile.PE(filepath)
final_pointer = -1

image_base = pe.OPTIONAL_HEADER.ImageBase

for section in pe.sections:
    va = section.VirtualAddress + image_base
    vs = section.Misc_VirtualSize
    ra = section.PointerToRawData
    ve = va + vs

    if target_va >= va and target_va <= ve:
        section_offset = target_va - va
        raw_address = ra
        final_pointer = section_offset + raw_address

if final_pointer == -1:
    print(f"{hex(target_va)} -> ??")
    exit(0)

print(f"{hex(target_va)} -> {hex(final_pointer)}")
exit(0)
