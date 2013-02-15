from vutils import *
def ms_SHLLINK_header():

	######################## [ MS-SHLLINK ] ########################
	# REFERENCE: [MS-SHLLINK].pdf
		
	# 2.1 SHELL_LINK_HEADER #
	HeaderSize = '' 	# LENGTH: 4 bytes.
	# The size, in bytes, of this structure. This value MUST be 0x0000004C.
		
	LinkCLSID = ''		# LENGTH: 16 bytes
	# A class identifier (CLSID). This value MUST be 
	# 00021401-0000-0000-C000-000000000046.

	LinkFlags = ''		# LENGTH: 4 bytes
	# A LinkFlags structure (section 2.1.1) that specifies information about 
	# the shell link and the presence of optional portions of the structure.
		
	FileAttributes = ''	# LENGTH: 4 bytes
	# A FileAttributesFlags structure (section 2.1.2) that specifies 
	# information about the link target.	

	CreationTime = ''	# LENGTH: 8 bytes
	# A FILETIME structure ([MS-DTYP] section 2.3.1) that specifies the 
	# creation time of the link target in UTC (Coordinated Universal Time). 
	# If the value is zero, there is no creation time set on the link target.
		
	AccessTime = ''		# LENGTH: 8 bytes
	# A FILETIME structure ([MS-DTYP] section 2.3.1) that specifies the access 
	# time of the link target in UTC (Coordinated Universal Time). If the value 
	# is zero, there is no access time set on the link target.
		
	WriteTime = ''		# LENGTH: 8 bytes
	# A FILETIME structure ([MS-DTYP] section 2.3.1) that specifies the write 
	# time of the link target in UTC (Coordinated Universal Time). If the value 
	# is zero, there is no write time set on the link target.
	
	FileSize = ''		# LENGTH: 4 bytes
	# A 32-bit unsigned integer that specifies the size, in bytes, of the link 
	# target. If the link target file is larger than 0xFFFFFFFF, this value 
	# specifies the least significant 32 bits of the link target file size.
		
	IconIndex = ''		# LENGTH: 4 bytes
	# A 32-bit signed integer that specifies the index of an icon within a 
	# given icon location.
	
	ShowCommand = ''	# LE
