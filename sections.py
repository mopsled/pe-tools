#!/usr/bin/env python

import os.path
import sys
import struct

def main():
	if len(sys.argv) != 2:
		print("Usage: %s file" % sys.argv[0])
		exit(0)

	file_name = sys.argv[1]

	if not os.path.isfile(file_name):
		error("Can't open file %s" % file_name)

	file_size = os.path.getsize(file_name)

	with open(file_name, "rb") as f:
		dos_magic = struct.unpack("<H", f.read(2))[0]
		if dos_magic != 0x5a4d:
			error("File is missing MS-DOS header (magic = %x). Can't read '%s'" % (dos_magic, file_name))

		safeseek(f, 0x3c, file_size)
		pe_offset = struct.unpack("<I", f.read(4))[0]

		safeseek(f, pe_offset, file_size)

		pe_magic = struct.unpack("<I", f.read(4))[0]
		if pe_magic != 0x4550:
			error("File is missing PE header (magic = %x). Can't read '%s'" % (pe_magic, file_name))

		safeseek(f, pe_offset + 0x18, file_size)
		pe_optional_magic = struct.unpack("<H", f.read(2))[0]
		if pe_optional_magic == 0x10b:
			debug("PE file is 32-bit")
		elif pe_optional_magic == 0x20b:
			debug("PE file is 64-bit")
		else:
			error("PE file has unrecognized optional PE header (magic = %x). Can't process '%x'" % (pe_optional_magic, file_name))

		safeseek(f, pe_offset + 6, file_size)
		number_of_sections = struct.unpack("<H", f.read(2))[0]
		debug("%d sections in file" % number_of_sections)

		safeseek(f, pe_offset + 0x14, file_size)
		optional_header_size = struct.unpack("<H", f.read(2))[0]

		current_section_offset = pe_offset + 0x18 + optional_header_size
		safeseek(f, current_section_offset, file_size)

		for n in range(number_of_sections):
			section_name = f.read(8)
			print "SECTION %d: %s" % (n, section_name)

			current_section_offset += 0x28
			safeseek(f, current_section_offset, file_size)

def safeseek(file_handle, address, file_size):
	if (address >= file_size):
		error("Attempted to seek past end of file. Aborting")
	else:
		file_handle.seek(address)

def error(message):
	print message
	exit(1)

def debug(message):
	print "DEBUG: %s" % message

if __name__ == '__main__':
	main()