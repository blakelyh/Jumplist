from vutils import *
def cfb_Header():
	# 2.2 COMPOUND FILE HEADER: MUST be at beginning of file (0x0) #
	Header_Signature = ''			# LENGTH: 8 bytes.
	# Identification signature for the compound file structure, and MUST be 
	# set to the value 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1.
	
	Header_CLSID = ''			# LENGTH: 16 bytes.
	# Reserved and unused class ID that MUST be set to all zeros (CLSID_NULL).

	Minor_Version = ''			# LENGTH: 2 bytes.
	# Version number for non-breaking changes. This field SHOULD be set to 
	# 0x003E if the major version field is either 0x0003 or 0x0004.

	Major_Version = '' 			# LENGTH: 2 bytes.
	# Version number for breaking changes. This field MUST be set to either
	# 0x0003 (version 3) or 0x0004 (version 4).
		
	Byte_Order = ''				# LENGTH: 2 bytes.
	# This field MUST be set to 0xFFFE. This field is a byte order mark for
	# all integer fields, specifying little-endian byte order.
	
	Sector_Shift = ''			# LENGTH: 2 bytes.
	# This field MUST be set to 0x0009, or 0x000c, depending on the Major 
	# Version field. This field specifies the sector size of the compound 
	# file as a power of 2.
	# If Major Version is 3, then the Sector Shift MUST be 0x0009, 
	# specifying a sector size of 512 bytes.
	# If Major Version is 4, then the Sector Shift MUST be 0x000C, 
	# specifying a sector size of 4096 bytes.

	Mini_Sector_Shift = ''			# LENGTH: 2
	# This field MUST be set to 0x0006. This field specifies the sector
	# size of the Mini Stream as a power of 2. The sector size of the 
	# Mini Stream MUST be 64 bytes.
		
	Reserved = ''				# LENGTH: 6 bytes.
	# This field MUST be set to all zeroes.

	Number_of_Directory_Sectors = ''	# LENGTH: 4 bytes.
	# This integer field contains the count of the number of directory 
	# sectors in the compound file. 
	# If Major Version is 3, then the Number of Directory Sectors MUST be 
	# zero. This field is not supported for version 3 compound files.

	Number_of_FAT_Sectors = ''		# LENGTH: 4 bytes.
	# This integer field contains the count of the number of FAT sectors 
	# in the compound file.

	First_Directory_Sector_Location = ''	# LENGTH: 4 bytes.
	# This integer field contains the starting sector number for the 
	# directory stream.

	Transaction_Signature_Number = ''	# LENGTH: 4 bytes.
	# This integer field MAY contain a sequence number that is incremented
	# every time the compound file is saved by an implementation that 
	# supports file transactions. This is field that MUST be set to all 
	# zeroes if file transactions are not implemented.
	
	Mini_Stream_Cutoff_Size = ''		# LENGTH: 4 bytes.
	# This integer field MUST be set to 0x00001000. This field specifies 
	# the maximum size of a user-defined data stream allocated from the 
	# mini FAT and mini stream, and that cutoff is 4096 bytes. Any user-
	# defined data stream larger than or equal to this cutoff size must be 
	# allocated as normal sectors from the FAT.
		
	First_Mini_FAT_Sector_Location = ''	# LENGTH: 4 bytes.
	# This integer field contains the starting sector number for the mini
	# FAT.
		
	Number_of_Mini_FAT_Sectors = ''		# LENGTH: 4 bytes.
	# This integer field contains the count of the number of mini FAT 
	# sectors in the compound file.
		
	First_DIFAT_Sector_Location = ''	# LENGTH: 4 bytes.
	# This integer field contains the starting sector number for the DIFAT.
		
	Number_of_DIFAT_Sectors = ''		# LENGTH: 4 bytes.
	# This integer field contains the count of the number of DIFAT sectors 
	# in the compound file.

	DIFAT = ''				# LENGTH: 436 bytes.
	# This array of 32-bit integer fields contains the first 109 FAT sector 
	# locations of the compound file.	
	# For version 4 compound files, the header size (512 bytes) is less 
	# than the sector size (4096 bytes), so the remaining part of the 
	# header (3584 bytes) MUST be filled with all zeroes.

