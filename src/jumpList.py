# Volatility
# Copyright (C) 2008 Volatile Systems
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the license, or (at
# your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

from vutils import *


## [ Jump List Enumeration ] ##
class jle(forensics.commands.command):

	######## Declare meta information associated with this plugin ########
	
	meta_info = forensics.commands.command.meta_info
	meta_info['author'] = 'Hunter Blakely, John Carlson'
	meta_info['copyright'] = 'Copyright (c) 2013 Hunter Blakely, John Carlson'
	meta_info['contact'] = 'blakelyh@sou.edu'
	meta_info['url'] = 'https://github.com/blakelyh/Jumplist'
	meta_info['os'] = 'Win7-Win8'
	meta_info['version'] = 'beta'
	

	 def parseMS_CFB():
	
		######################## [ MS_CFB FORMAT ] ########################
		# REFERENCE: [MS-CFB].pdf


		# 2.1 Compound File Sector Numbers and Types #
		REGSECT	= 0x00000000 - 0xFFFFFFF9	# Regular Sector number
		# REGSECT may need to be broken into regsectLow & regsectHigh
		# due to the range value given.
		
		MAXREGSECT = 0xFFFFFFFA	# Maximum regular sector number
		
		DIFSECT = 0xFFFFFFFC	# Specifies a DIFAT sector in the FAT
		
		FATSECT = 0xFFFFFFFD	# Specifies a FAT sector in the FAT	
		
		ENDOFCHAIN = 0xFFFFFFFE	# End of linked chain of sectors
		
		FREESECT = 0xFFFFFFFF	# Specifies unallocated sector in the \
					# FAT, Mini FAT, or DIFAT
		




		# Compound File Binary File Format #
		Header = ''	# LENGTH: N/A.
				# A single sector with fields needed to read the
				# other structures of the compound file. This 
				# structure must be at file offset 0.
		
		FAT = ''	# LENGTH: 4 bytes. 
				# Main allocation of space within the compound file.
				
		DIFAT = ''	# LENGTH: 4 bytes. 
				# Used to locate FAT sectors in the compound file.

		Mini_FAT = ''	# LENGTH: 4 bytes. 
				# Allocator for mini stream user-defined data.

		Directory = ''	# LENGTH: 128 bytes. 
				# Contains storage object and stream object metadata.

		User-defined_Data = '' 	# LENGTH: N/A.
					# User-defined data for stream objects.
		
		Range_Lock = ''		# LENGTH: N/A.
					# A single sector used to manage concurrent
					# access to the compound file. This sector
					# must cover file offset 0x7FFFFFFF.

		Unallocated_Free = ''	# LENGTH: N/A.
					# Empty space in the compound file.	





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
		

		

		# 2.3 Compound File FAT Sectors #
		Next_Sector_in_Chain = ''		# LENGTH: variable
		# This field specifies the next sector number in a chain of sectors.
		# If Header Major Version is 3, then there MUST be 128 fields specified 
		# to fill a 512-byte sector.
		# If Header Major Version is 4, then there MUST be 1024 fields specified
		# to fill a 4096-byte sector.

		


		# 2.4 Compound File Mini FAT Sectors #
		Next_Sector_in_Chain_Mini = ''		# LENGTH: variable
		# This field specifies the next sector number in a chain of sectors.
		# If Header Major Version is 3, then there MUST be 128 fields specified 
		# to fill a 512-byte sector.
		# If Header Major Version is 4, then there MUST be 1024 fields specified
		# to fill a 4096-byte sector.




		# 2.5 Compound File DIFAT Sectors #
		FAT_Sector_Location = ''		# LENGTH: variable.
		# This field specifies the FAT sector number in a DIFAT. 
		# If Header Major Version is 3, then there MUST be 127 fields specified 
		# to fill a 512-byte sector minus the "Next DIFAT Sector Location" field.
		# If Header Major Version is 4, then there MUST be 1023 fields specified 
		# to fill a 4096-byte sector minus the "Next DIFAT Sector Location"
		# field. 
		
		Next_DIFAT_Sector_Location = ''		# LENGTH: variable.
		# This field specifies the next sector number in the DIFAT chain of 
		# sectors. The first DIFAT sector is specified in the Header. The last 
		# DIFAT sector MUST set this field to ENDOFCHAIN (0xFFFFFFFE).




		# 2.6 Compound File Directory Sectors #
		# The directory entry array is a structure used to contain information 
		# about the stream and storage objects in a compound file, and to 
		# maintain a tree-style containment structure. The directory entry 
		# array is allocated as a standard chain of directory sectors within 
		# the FAT. Each directory entry is identified by a non-negative number 
		# called the stream ID. The first sector of the directory sector chain 
		# MUST contain the root storage directory entry as the first directory 
		# entry at stream ID 0.
		
		# 2.6.1 Compound File Directory Entry #
		REGSID = 0x00000000 through 0xFFFFFFF9 # Regular stream ID to identify 
		# directory entry.
		
		MAXREGSID = 0xFFFFFFFA	# Maximum regular stream ID.
		
		NOSTREAM = 0xFFFFFFFF	# Terminator or empty pointer.

		Directory_Entry_Name = ''	# LENGTH: 64 bytes.
		# This field MUST contain a Unicode string for the storage or stream 
		# name encoded in UTF-16. The name MUST be terminated with a UTF-16 
		# terminating null character. Thus storage and stream names are limited 
		# to 32 UTF-16 code points, including the terminating null character. 
		# When locating an object in the compound file except for the root 
		# storage, the directory entry name is compared using a special case-
		# insensitive upper- case mapping, described in Red-Black Tree. The 
		# following characters are illegal and MUST NOT be part of the name: 
		# '/', '\', ':', '!'.

		Directory_Entry_Name_Length = ''	# LENGTH: 2 bytes.
		# This field MUST match the length of the Directory Entry Name Unicode 
		# string in bytes. The length MUST be a multiple of 2, and include the 
		# terminating null character in the count. This length MUST NOT exceed 
		# 64, the maximum size of the Directory Entry Name field.

		Object_Type = ''	# LENGTH: 1 byte
		# This field MUST be 0x00, 0x01, 0x02, or 0x05, depending on the 
		# actual type of object. All other values are not valid.

		Color_Flag = ''		# LENGTH: 1 byte.
		# This field MUST be 0x00 (red) or 0x01 (black). All other values are 
		# not valid.

		Left_Sibling_ID = ''	# LENGTH: 4 bytes
		# This field contains the Stream ID of the left sibling. If there is 
		# no left sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF).

		Right_Sibling_ID = ''	# LENGTH: 4 bytes
		# This field contains the Stream ID of the right sibling. If there is 
		# no right sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF).

		Child_ID = ''		# LENGTH: 4 bytes
		# This field contains the Stream ID of a child object. If there is 
		# no child object, then the field MUST be set to NOSTREAM (0xFFFFFFFF).
	
		CLSID = ''		# LENGTH: 16 bytes
		# This field contains an object class GUID, if this entry is a storage 
		# or root storage. If there is no object class GUID set on this object, 
		# then the field MUST be set to all zeroes. In a stream object, this 
		# field MUST be set to all zeroes. If not NULL, the object class GUID 
		# can be used as a parameter to launch applications.

		State_Bits = ''		# LENGTH: 4 bytes 
		# This field contains the user-defined flags if this entry is a 
		# storage object or root storage object. If there are no state bits 
		# set on the object, then this field MUST be set to all zeroes.

		Creation_Time = '' 	# LENGTH: 8 bytes
		# This field contains the creation time for a storage object. The 
		# Windows FILETIME structure is used to represent this field in UTC. 
		# If there is no creation time set on the object, this field MUST be 
		# all zeroes. For a root storage object, this field MUST be all zeroes, 
		# and the creation time is retrieved or set on the compound file itself.
		
		Modified_Time = ''	# LENGTH: 8 bytes
		# This field contains the modification time for a storage object. The 
		# Windows FILETIME structure is used to represent this field in UTC. 
		# If there is no modified time set on the object, this field MUST be 
		# all zeroes. For a root storage object, this field MUST be all zeroes, 
		# and the modified time is retrieved or set on the compound file itself.

		Starting_Sector_Location = '' 	# LENGTH 4 bytes
		# This field contains the first sector location if this is a stream 
		# object. For a root storage object, this field MUST contain the first 
		# sector of the mini stream, if the mini stream exists.
		
		Stream_Size = ''	# LENGTH: 8 bytes
		# This 64-bit integer field contains the size of the user-defined data, 
		# if this is a stream object. For a root storage object, this field 
		# contains the size of the mini stream.
		


	def parseMS_SHLLINK():
	
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
	
		ShowCommand = ''	# LENGTH: 4 bytes
		# A 32-bit unsigned integer that specifies the expected window state of an 
		# application launched by the link. This value SHOULD be one of the 
		# following.

		HotKey = ''		# LENGTH: 2 bytes
		# A HotKeyFlags structure (section 2.1.3) that specifies the keystrokes 
		# used to launch the application referenced by the shortcut key. This value 
		# is assigned to the application after it is launched, so that pressing the 
		# key activates that application.

		Reserved1 = ''		# LENGTH: 2 bytes 
		# A value that MUST be zero.

		Reserved2 = ''		# LENGTH: 4 bytes 
		# A value that MUST be zero.

		Reserved3 = ''		# LENGTH: 4 bytes
		# A value that MUST be zero.


		

		# 2.1.1 LINK_FLAGS # 
		
		







	# def DecryptJumpListID():
		# return nameOfJumpList

