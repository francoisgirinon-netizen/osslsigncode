#!/usr/bin/python3
"""Check that the CheckSum field of PE files matches their content."""

import struct
import sys


def pe_checksum(data: bytes) -> int:
    """Compute the PE checksum, with the CheckSum field taken as zero."""
    field = struct.unpack_from("<I", data, 60)[0] + 88
    data = data[:field] + bytes(4) + data[field + 4:]
    size = len(data) & ~1
    total = sum(struct.unpack_from("<{}H".format(size // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + size) & 0xFFFFFFFF


def main() -> None:
    """Check each file given on the command line."""
    if len(sys.argv) < 2:
        print("Usage:\n\t{} FILE...".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    failed = 0
    for path in sys.argv[1:]:
        with open(path, mode="rb") as file:
            data = file.read()
        stored = struct.unpack_from("<I", data, struct.unpack_from("<I", data, 60)[0] + 88)[0]
        computed = pe_checksum(data)
        print("{}: stored {:08X}, computed {:08X}".format(path, stored, computed))
        if stored != computed:
            failed = 1
    sys.exit(failed)


if __name__ == "__main__":
    main()


# pylint: disable=pointless-string-statement
"""Local Variables:
    c-basic-offset: 4
    tab-width: 4
    indent-tabs-mode: nil
End:
    vim: set ts=4 expandtab:
"""
