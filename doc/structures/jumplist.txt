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



		# 1.2 References # 
		# References to Microsoft Open Specifications documentation do not include
		# a publishing year because links are to the latest version of the 
		# documents, which are updated frequently. References to other documents
		# include a publishing year when one is available.




		#  1.2.1 Normative References #
		# http://msdn2.microsoft.com/en-us/library/E4BD6494-06AD-4aed-9823-
		# 445E921C9624, as an additional source.
		# [MS-DTYP] Microsoft Corporation, "Windows Data Types".
		# [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement 
		# Levels", BCP 14, RFC
		# 2119, March 1997, http://www.rfc-editor.org/rfc/rfc2119.txt
		# [UNICODE3.0.1] The Unicode Consortium, "Unicode Default Case Conversion 
		# Algorithm 3.0.1",
		# August 2001, http://www.unicode.org/Public/3.1-Update1/CaseFolding-4.txt
		# [UNICODE5.0.0] The Unicode Consortium, "Unicode Default Case Conversion 
		# Algorithm 5.0.0",
		# March 2006, http://www.unicode.org/Public/5.0.0/ucd/CaseFolding.txt
		


		

		# 1.2.2 # 
		# [MS-GLOS] Microsoft Corporation, "Windows Protocols Master Glossary".
		# [MS-OLEDS] Microsoft Corporation, "Object Linking and Embedding (OLE) 
		# Data Structures".
		# [MS-OLEPS] Microsoft Corporation, "Object Linking and Embedding (OLE) 
		# Property Set Data Structures".





	
		# 1.3 Overview # 
		# A compound file is a structure used to store a hierarchy of storage 
		# objects and stream objects into a single file or memory buffer.
		# A storage object is analogous to a file system directory. Just as a 
		# directory can contain other directories and files, a storage object can 
		# contain other storage objects and stream objects. Also like a directory, 
		# a storage object tracks the locations and sizes of the child storage 
		# object and stream objects nested beneath it.
		# A stream object is analogous to the traditional notion of a file. Like 
		# a file, a stream contains user- defined data stored as a consecutive 
		# sequence of bytes.

		# The hierarchy is defined by a parent object/child object relationship. 
		# Stream objects cannot contain child objects. Storage objects can contain 
		# stream objects and/or other storage objects, each of which has a name 
		# that uniquely identifies it among the children of its parent storage 
		# object.

		# The root storage object has no parent object. The root storage object 
		# also has no name; because names are used to identify child objects, a 
		# name for the root storage object is unnecessary and the file format does 
		# not provide a representation for it.

		# A compound file consists of the root storage object with optional child
		# storage objects and stream objects in a nested hierarchy. Stream objects 
		# can contain user-defined data stored as an array of bytes. Storage 
		# objects can contain an object class GUID called a CLSID, which can 
		# identify an application that can read/write stream objects under that 
		# storage object.

		# A compound file is divided into equal-length sectors. The first sector 
		# contains the compound file header. Subsequent sectors are identified by 
		# a 32-bit non-negative integer number, called the sector number.
		# A group of sectors can form a sector chain, which is a linked list of 
		# sectors forming a logical byte array, even though the sectors can be in 
		# non-consecutive locations in the compound file. For example, shown are 
		# two sector chains. A sector chain starts at sector #0, continues to 
		# sector #2, and ends at sector #4. Another sector chain starts at sector 
		# #1, and ends at sector #3.

		# A sector can be unallocated or free, in which case it is not part of a 
		# sector chain. A sector number is used for several purposes.
		# ￼￼￼1. A sector number is used to identify the file offset of that sector 
		# in a compound file. 2. In a sector chain, it is used to identify the 
		# next sector in the chain.
		# 3. Special sector numbers are used to represent chain termination and 
		# free sectors.




		
		# 1.4 Relationship to Protocols and Other Structures #
		# [MS-DTYP], "Windows Data Types", Revision 3.0, September 2007, 
		# MS-DTYP-v1.02.doc The compound file internal structures use the following 
		# Microsoft Windows® data types:
		# FILETIME for storage timestamps.
		# GUID for storage objects object class ID.
		# ULONGLONG for stream sizes.
		# DWORD for sector numbers and various size fields.
		# USHORT for header and directory fields.
		# BYTE for header and directory fields.
		# WCHAR for storage and stream names.
		# [MS-OLEPS] Microsoft OLE Property Set Data Structures Specification
		# OLE property sets are a standard set of stream formats that are typically
		# implemented as compound file stream objects. Most applications that save
		# their data in compound files also write out summary information property
		# set data in the OLE property sets stream formats.
		# [MS-OLEDS] Microsoft OLE Data Structures: Structure Specification
		# OLE linking and embedding streams and storages are used to contain data 
		# used by outside applications that implement the OLE interfaces and APIs.
		# [UNICODE3.0.1] The Unicode Consortium, "Unicode Default Case Conversion 
		# Algorithm", Version 3.0.1, August 2001, 
		# http://www.unicode.org/Public/3.1-Update1/CaseFolding-4.txt
		# [UNICODE5.0.0] The Unicode Consortium, "Unicode Default Case Conversion 
		# Algorithm", Version 5.0.0, March 2006, 
		# http://www.unicode.org/Public/5.0.0/ucd/CaseFolding.txt
		



		# 1.5 Applicability Statement #
		# This protocol structure is recommended for persisting objects in a random 
		# access file system or random access memory system.
		# This protocol is not recommended for real-time streaming, progressive 
		# rendering, or open-ended data protocols where the size of streams is 
		# unknown when the compound file is transmitted. The known size of all 
		# structures within a compound file must be specified when the compound 
		# file is transmitted or retrieved.




		# 1.6 Versioning and Localization # 
		# This document covers versioning issues in the following areas:
		# Structure Versions: There are two versions of the compound file structure,
		# version 3 and version 4. These versions are defined in section 2.2. In a 
		# version 4 compound file, all features of version 3 MUST be implemented.
		# Implementations MUST return an error when encountering a higher version 
		# than supported. For example, if only version 3 compound file is supported,
		# the implementation MUST return an error if a version 4 compound file is 
		# being opened.
		# Localization: There is no localization-dependent structure content in the 
		# compound file structure. In the implementation, all Unicode character 
		# comparisons MUST be locale-invariant and all timestamps MUST be stored in 
		# UTC time-zone.



		# 1.7 Vendor-Extensible Fields #
		# A compound file does not contain any vendor-extensible fields. However, a 
		# compound file does contain ways to store user-defined data in storage 
		# objects and stream objects. The vendor can store vendor-specific data in 
		# user-defined data.




		# 2 Structures # 
		# This document references commonly used data types as defined in [MS-DTYP].
		# Unless otherwise qualified, instances of GUID in this section refer to
		# [MS-DTYP] section 2.3.2.
		# The main structure used to manage sector allocation and sector chains is
		# the file allocation table (FAT). The FAT contains an array of 32-bit 
		# sector numbers, where the index represents a sector number, and its value
		# represents the next sector in the chain, or a special value.
		# FAT[0] contains sector #0's next sector in chain
		# FAT[1] contains sector #1's next sector in chain
		# ...
		# FAT[N] contains sector #N's next sector in chain
		# This allows a compound file to contain many sector chains in a single 
		# file. Many compound file structures, including user-defined data, are 
		# implemented as sector chains represented in the FAT.
		# Even the FAT array itself is represented as a sector chain. The sector 
		# chain holds both internal and user-defined data streams. Because the FAT 
		# array is stored in a sector chain, the DIFAT array is used to find the 
		# FAT sector locations. Each DIFAT array entry contains a 32-bit sector 
		# number.
		# DIFAT[0] contains FAT sector #0's location 
		# DIFAT[1] contains FAT sector #1's location 
		# ...
		# DIFAT[N] contains FAT sector #N's location
		# Because space for streams is always allocated in sector-sized blocks, 
		# there can be considerable waste when storing objects much smaller than 
		# the normal sector size (either 512 or 4096 bytes). As a solution to this 
		# problem, the concept of the mini FAT is introduced.

		# The mini FAT is structurally equivalent to the FAT, but is used in a 
		# different way. The sector size for objects represented in mini FAT is 
		# 64 bytes, instead of the 512-bytes or 4096-bytes for normal sectors. 
		# The space for these objects comes from a special stream called the mini 
		# stream. The mini stream is an internal stream object divided into 
		# equal-length mini sectors. Each mini FAT array entry contains a 32-bit 
		# sector number for the mini stream, not the file.
		# MiniFAT[0] contains mini stream sector #0's next sector in chain 
		# MiniFAT[1] contains mini stream sector #1's next sector in chain 
		# ...
		# MiniFAT[N] contains mini stream sector #N's next sector in chain
		# Stream objects with a user-defined data length less than a cutoff 
		# (4096 bytes) are allocated with the mini FAT from the mini stream. 
		# Larger stream objects are allocated with the FAT from unallocated free 
		# sectors in the file.
		# The names of all storage objects and stream objects, along with other 
		# object metadata like stream size and storage CLSIDs, are found in the 
		# directory entry array. The space for the directory entry array is 
		# allocated with the FAT like other sector chains.
		# DirectoryEntry[0] contains information about the root storage object.
		# DirectoryEntry[1] contains information about a storage object, 
		# stream object, or unallocated object. 
		# ...
		# DirectoryEntry[N] contains information about a storage object, 
		# stream object, or unallocated object.
		 	
		# Figure 9: Summary of compound file internal streams and connections to 
		# user-defined data streams
		# This diagram summarizes the compound file main internal streams and how 
		# they are linked to user- defined data streams. The DIFAT, FAT, mini FAT, 
		# directory entry arrays, and mini stream are internal streams, while the 
		# user-defined data streams link directly to their stream objects.
		# In a compound file, all integer fields, including Unicode characters 
		# encoded in UTF-16, MUST be stored in little-endian byte order. The only 
		# exception is in user-defined data streams, where the compound file 
		# structure does not impose any restrictions.
		


 


		# 2.1 Compound File Sector Numbers and Types #
		# Each sector, except for the header, is identified by a non-negative 
		# 32-bit sector number. The following sector numbers above 0xFFFFFFFA are 
		# reserved, and MUST NOT be used to identify the location of a sector in a 
		# compound file.	

		# REGSECT may need to be broken into regsectLow & regsectHigh
		# due to the range value given.
		# Regular Sector number: 0x00000000 -> 0xFFFFFFF9 
		REGSECT	= ''	
		
		# Low bound of REGSECT
		REGSECT_LOW = 0x00000000 	
		
		# High bound of REGSECT
		REGSECT_HIGH = 0xFFFFFFF9	
		

		# Maximum regular sector number
		MAXREGSECT = 0xFFFFFFFA		
	
		# Specifies a DIFAT sector in the FAT
		DIFSECT = 0xFFFFFFFC			
	
		# Specifies a FAT sector in the FAT	
		FATSECT = 0xFFFFFFFD	
		
		# End of linked chain of sectors
		ENDOFCHAIN = 0xFFFFFFFE			
	
		# Specifies unallocated sector in the FAT, Mini FAT, or DIFAT
		FREESECT = 0xFFFFFFFF			

		# Compound File Binary File Format 
		# Compound file sectors can contain unallocated free space, user-defined 
		# data for stream objects, directory sectors containing directory entries, 
		# FAT sectors containing the FAT entries, DIFAT sectors containing the 
		# DIFAT entries, and mini FAT sectors containing the mini FAT entries. 
		# Compound file sectors can be located at any sector-sized offset in the 
		# file, with the exception of the header and range lock sector.
		
		# All the sector types are eventually linked back to the header sector, 
		# except for the range lock sector and unallocated free sectors. 
		# Unallocated free sectors are marked in the FAT as FREESECT (0xFFFFFFFF). 
		# Unallocated free sectors can be in the middle of the file, and can be 
		# created by extending the file size and allocating additional FAT sectors 
		# to cover the increased length. The range lock sector is identified by a 
		# fixed file offset (0x7FFFFFFF) in the compound file.
		
		# In a compound file, all sector chains MUST contain valid sector numbers, 
		# less than or equal to MAXREGSECT (0xFFFFFFFA). In a sector chain, the 
		# last sector's next pointer MUST be ENDOFCHAIN (0xFFFFFFFE). All sectors 
		# in a sector chain MUST NOT be part of any other sector chain in the same 
		# file. A sector chain MUST NOT link to a sector appearing earlier in the 
		# same chain, which would result in a cycle. Finally, the actual sector 
		# count MUST match the size specified for a sector chain.

		# A single sector with fields needed to read the other structures of the 
		# compound file. This structure must be at file offset 0.
		Header = ''	# LENGTH: N/A.
						
		# Main allocation of space within the compound file.
		FAT = ''	# LENGTH: 4 bytes. 
								
		# Used to locate FAT sectors in the compound file.
		DIFAT = ''	# LENGTH: 4 bytes. 
	
		# Allocator for mini stream user-defined data.		
		Mini_FAT = ''	# LENGTH: 4 bytes. 
				
		# Contains storage object and stream object metadata.
		Directory = ''	# LENGTH: 128 bytes. 
	
		# User-defined data for stream objects.
		User-defined_Data = '' 	# LENGTH: N/A.
							
		# A single sector used to manage concurrent access to the compound file. 
		# This sector must cover file offset 0x7FFFFFFF.
		Range_Lock = ''		# LENGTH: N/A.

		# Empty space in the compound file.
		Unallocated_Free = ''	# LENGTH: N/A.
						




		# 2.2 COMPOUND FILE HEADER: MUST be at beginning of file (0x0) #
		# The Compound File Header structure MUST be at the beginning of the file
		# (offset 0).			
		
		# Identification signature for the compound file structure, and MUST be 
		# set to the value 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1.
		Header_Signature = ''			# LENGTH: 8 bytes.
		switch(Header_Signature):
			case 0xD0:
			break;
			case 0xCF:
			break;
			case 0x11:
			break;
			case 0xE0:
			break;
			case 0xA1:
			break;
			case 0xB1:
			break;
			case 0x1A:
			break;
			case 0xE1:
			break;
			default:
				printf("ERROR: Inapropriate Header Signature.")
			break;

		# Reserved and unused class ID that MUST be set to all zeros (CLSID_NULL).
		Header_CLSID = ''			# LENGTH: 16 bytes.

		# Version number for non-breaking changes. This field SHOULD be set to 
		# 0x003E if the major version field is either 0x0003 or 0x0004.		
		Minor_Version = ''			# LENGTH: 2 bytes.
		if(Minor_Version == 0x003E):
			printf("Major_Version	is either 0x0003, or 0x0004")

		# Version number for breaking changes. This field MUST be set to either
		# 0x0003 (version 3) or 0x0004 (version 4).
		Major_Version = '' 			# LENGTH: 2 bytes.
		if (Major_Version == 0x0003):
			printf("Version is 3")
		elif (Major_Version == 0x0004):
			printf("Version is 4.")		
		
		# This field MUST be set to 0xFFFE. This field is a byte order mark for
		# all integer fields, specifying little-endian byte order.
		Byte_Order = ''				# LENGTH: 2 bytes.
		if (Byte_Order != 0xFFFE):
			printf("ERROR: Byte Order must be set to 0xFFFE, it is: "\
			 +Byte_Order)

		# This field MUST be set to 0x0009, or 0x000c, depending on the Major 
		# Version field. This field specifies the sector size of the compound 
		# file as a power of 2.
		# If Major Version is 3, then the Sector Shift MUST be 0x0009, 
		# specifying a sector size of 512 bytes.
		# If Major Version is 4, then the Sector Shift MUST be 0x000C, 
		# specifying a sector size of 4096 bytes.
		Sector_Shift = ''			# LENGTH: 2 bytes.
		if (Major_Version == 0x0003):
			Sector_Shift = 0x0009
		elif (Major_Version == 0x0004):
			Sector_Shift = 0x000C

		# This field MUST be set to 0x0006. This field specifies the sector
		# size of the Mini Stream as a power of 2. The sector size of the 
		# Mini Stream MUST be 64 bytes.
		Mini_Sector_Shift = ''			# LENGTH: 2
		if (Mini_Sector_Shift != 0x0006):
			printf("ERROR, the sector size MUST be 64 bytes.")
		
		# This field MUST be set to all zeroes.		
		Reserved = ''				# LENGTH: 6 bytes.
		if (Reserved != 0):
			printf("Error, Reserved must be (x48) 0's")
	
		# This integer field contains the count of the number of directory 
		# sectors in the compound file. 
		# If Major Version is 3, then the Number of Directory Sectors MUST be 
		# zero. This field is not supported for version 3 compound files.
		Number_of_Directory_Sectors = ''	# LENGTH: 4 bytes.
		if (Major_Version == 0x0003):
			if (Number_of_Directory_Sectors != 0x00000000):
				printf("Error, If version is 3, numDirSect must be 0")
	
		# This integer field contains the count of the number of FAT sectors 
		# in the compound file.
		Number_of_FAT_Sectors = ''		# LENGTH: 4 bytes.		

		# This integer field contains the starting sector number for the 
		# directory stream.
		First_Directory_Sector_Location = ''	# LENGTH: 4 bytes.
			
		# This integer field MAY contain a sequence number that is incremented
		# every time the compound file is saved by an implementation that 
		# supports file transactions. This is field that MUST be set to all 
		# zeroes if file transactions are not implemented.
		Transaction_Signature_Number = ''	# LENGTH: 4 bytes.
		if (Transaction_Signature_Number == 0):
			printf("File transactions are not implemented.")
	
		# This integer field MUST be set to 0x00001000. This field specifies 
		# the maximum size of a user-defined data stream allocated from the 
		# mini FAT and mini stream, and that cutoff is 4096 bytes. Any user-
		# defined data stream larger than or equal to this cutoff size must be 
		# allocated as normal sectors from the FAT.
		Mini_Stream_Cutoff_Size = ''		# LENGTH: 4 bytes.
		if (Mini_Stream_Cutoff_Size != 0x00001000):
			printf("Error, max size must be: 0x00001000")
		
		# This integer field contains the starting sector number for the mini
		# FAT.
		First_Mini_FAT_Sector_Location = ''	# LENGTH: 4 bytes.
		
		# This integer field contains the count of the number of mini FAT 
		# sectors in the compound file.
		Number_of_Mini_FAT_Sectors = ''		# LENGTH: 4 bytes.
		
		# This integer field contains the starting sector number for the DIFAT.	
		First_DIFAT_Sector_Location = ''	# LENGTH: 4 bytes.
		
		# This integer field contains the count of the number of DIFAT sectors 
		# in the compound file.
		Number_of_DIFAT_Sectors = ''		# LENGTH: 4 bytes.
		
		# This array of 32-bit integer fields contains the first 109 FAT sector 
		# locations of the compound file.	
		# For version 4 compound files, the header size (512 bytes) is less 
		# than the sector size (4096 bytes), so the remaining part of the 
		# header (3584 bytes) MUST be filled with all zeroes.
		DIFAT = ''				# LENGTH: 436 bytes.	

		



		# 2.3 Compound File FAT Sectors #
		# The FAT is the main allocator for space within a compound file. Every 
		# sector in the file is represented within the FAT in some fashion, 
		# including those sectors that are unallocated (free). The FAT is a sector 
		# chain made up of one or more FAT sectors.
	
		# The FAT is an array of sector numbers that represent the allocation of 
		# space within the file, grouped into FAT sectors. Each stream is 
		# represented in the FAT by a sector chain, in much the same fashion as a 
		# FAT file system.
		# The set of FAT sectors can be considered together as a single array.
		# Each entry in that array contains the sector number of the next sector in
		# the chain, and this sector number can be used as an index into the FAT
		# array to continue along the chain.
		# Special values are reserved for chain terminators 
		# (ENDOFCHAIN = 0xFFFFFFFE), free sectors (FREESECT = 0xFFFFFFFF), and 
		# sectors that contain storage for FAT sectors (FATSECT = 0xFFFFFFFD) or 
		# DIFAT Sectors (DIFSECT = 0xFFFFFFC), which are not chained in the same
		# way as the others.
		# The locations of FAT sectors are read from the DIFAT, which is described
		# below. The FAT is represented in itself, but not by a chain. A special 
		# reserved sector number (FATSECT = 0xFFFFFFFD) is used to mark sectors 
		# allocated to the FAT.
		# A sector number can be converted into a byte offset into the file by 
		# using the following formula: (sector number + 1) x Sector Size. This 
		# implies that sector #0 of the file begins at byte offset Sector Size, 
		# not at 0.

		# This field specifies the next sector number in a chain of sectors.
		# If Header Major Version is 3, then there MUST be 128 fields specified 
		# to fill a 512-byte sector.
		# If Header Major Version is 4, then there MUST be 1024 fields specified
		# to fill a 4096-byte sector.
		Next_Sector_in_Chain = ''		# LENGTH: variable
		if (Major_Version == 0x0003):
			printf("128 fields specified to fill a 512-byte sector")
		elif(Major_Version == 0x0004):
			printf("1024 fields specified to fill a 4096-byte sector")
		




		# 2.4 Compound File Mini FAT Sectors #
		# The mini FAT is used to allocate space in the mini stream. The mini 
		# stream is divided into smaller, equal-length sectors, and the sector 
		# size used for the mini stream is specified from the Compound File Header
		# (64 bytes).

		# The locations for mini FAT sectors are stored in a standard chain in the
		# FAT, with the beginning of the chain stored in the header (first mini FAT
		# starting sector location).
		# A mini FAT sector number can be converted into a byte offset into the
		# mini stream by using the following formula: sector number x 64 bytes.
		# This formula is different from the formula used to convert a sector
		# number into a byte offset in the file, because no header is stored in the
		# mini stream.
		# The mini stream is chained within the FAT in exactly the same fashion as
		# any normal stream. The mini stream's starting sector is referenced in the
		# first directory entry (root storage stream ID 0).
		# If all of the user streams in the file are greater than the cutoff of 
		# 4096 bytes, then mini FAT and mini stream are not required. In this case,
		# the header's first mini FAT starting sector location can be set to
		# ENDOFCHAIN, and the root directory entry's starting sector location can
		# be set to ENDOFCHAIN.
		
		# This field specifies the next sector number in a chain of sectors.
		# If Header Major Version is 3, then there MUST be 128 fields specified 
		# to fill a 512-byte sector.
		# If Header Major Version is 4, then there MUST be 1024 fields specified
		# to fill a 4096-byte sector.	
		Next_Sector_in_Chain_Mini = ''		# LENGTH: variable
		




		# 2.5 Compound File DIFAT Sectors #
		# The DIFAT array is used to represent storage of the FAT sectors. The
		# DIFAT is represented by an array of 32-bit sector numbers. The DIFAT 
		# array is stored both in the header and in DIFAT sectors.
		# In the header, the DIFAT array occupies 109 entries, and in each DIFAT
		# sector, the DIFAT array occupies the entire sector minus 4 bytes (the 
		# last field is for chaining the DIFAT sector chain).

		# The DIFAT sectors are linked together by the last field in each DIFAT 
		# sector. As an optimization, the first 109 FAT sectors are represented 
		# within the header itself. No DIFAT sectors will be needed in a compound 
		# file that is smaller than 6.875 megabyte (MB) for a 512 byte sector 
		# compound file (6.875 MB = (1 header sector + 109 FAT sectors x 128 
		# non-empty entries) × 512 bytes per sector).

		# The DIFAT represents the FAT sectors in a different manner than the FAT
		# represents a sector chain. A given index, n, into the DIFAT array will
		# contain the sector number of the (n+1)th FAT sector. For instance, index
		# #3 in the DIFAT contains the sector number for the 4rd FAT sector, since
		# DIFAT array starts with index #0.

		# The storage for DIFAT sectors is reserved with the FAT, but it is not
		# chained there. Space for DIFAT sectors is marked by a special sector 
		# number, DIFSECT (0xFFFFFFFC).

		# The location of the first DIFAT sector is stored in the header.

		# A special value of ENDOFCHAIN (0xFFFFFFFE) is stored in "Next DIFAT 
		# Sector Location" field of the last DIFAT sector, or in the header when no
		# DIFAT sectors are needed.

		# This field specifies the FAT sector number in a DIFAT. 
		# If Header Major Version is 3, then there MUST be 127 fields specified 
		# to fill a 512-byte sector minus the "Next DIFAT Sector Location" field.
		# If Header Major Version is 4, then there MUST be 1023 fields specified 
		# to fill a 4096-byte sector minus the "Next DIFAT Sector Location"
		# field. 
		FAT_Sector_Location = ''		# LENGTH: variable.
		
		# This field specifies the next sector number in the DIFAT chain of 
		# sectors. The first DIFAT sector is specified in the Header. The last 
		# DIFAT sector MUST set this field to ENDOFCHAIN (0xFFFFFFFE).
		Next_DIFAT_Sector_Location = ''		# LENGTH: variable.
		if (Next_DIFAT_Sector_Location == 0xFFFFFFFE):
			printf("End of chain has been reached")





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
		# Regular stream ID to identify directory entry.
		# 0x00000000 through 0xFFFFFFF9 		
		REGSID = '' 		
		
		# Low end value for REGSID = 0x00000000
		REGSID_LOW = 0x00000000

		# High end value for REGSID = 0xFFFFFFF9 
		REGSID_HIGH = 0xFFFFFFF9 

		# Maximum regular stream ID.
		MAXREGSID = 0xFFFFFFFA	
		
		# Terminator or empty pointer.
		NOSTREAM = 0xFFFFFFFF	

		# The directory entry size is fixed at 128 bytes. The name in the directory
		# entry is limited to 32 Unicode UTF-16 code points, including the required
		# Unicode terminating null character.

		# Directory entries are grouped into blocks to form directory sectors. 
		# There are four directory entries in a 512-byte directory sector 
		# (version 3 compound file), and there are 32 directory entries in a 
		# 4096-byte directory sector (version 4 compound file). The number of
		# directory entries can exceed the number of storage objects and stream 
		# objects due to unallocated directory entries.

		# This field MUST contain a Unicode string for the storage or stream 
		# name encoded in UTF-16. The name MUST be terminated with a UTF-16 
		# terminating null character. Thus storage and stream names are limited 
		# to 32 UTF-16 code points, including the terminating null character. 
		# When locating an object in the compound file except for the root 
		# storage, the directory entry name is compared using a special case-
		# insensitive upper- case mapping, described in Red-Black Tree. The 
		# following characters are illegal and MUST NOT be part of the name: 
		# '/', '\', ':', '!'.
		Directory_Entry_Name = ''	# LENGTH: 64 bytes.
	
		# This field MUST match the length of the Directory Entry Name Unicode 
		# string in bytes. The length MUST be a multiple of 2, and include the 
		# terminating null character in the count. This length MUST NOT exceed 
		# 64, the maximum size of the Directory Entry Name field.
		Directory_Entry_Name_Length = ''	# LENGTH: 2 bytes.

		# This field MUST be 0x00, 0x01, 0x02, or 0x05, depending on the 
		# actual type of object. All other values are not valid.
		Object_Type = ''	# LENGTH: 1 byte

		# This field MUST be 0x00 (red) or 0x01 (black). All other values are 
		# not valid.
		Color_Flag = ''		# LENGTH: 1 byte.

		# This field contains the Stream ID of the left sibling. If there is 
		# no left sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF).
		Left_Sibling_ID = ''	# LENGTH: 4 bytes

		# This field contains the Stream ID of the right sibling. If there is 
		# no right sibling, the field MUST be set to NOSTREAM (0xFFFFFFFF).
		Right_Sibling_ID = ''	# LENGTH: 4 bytes

		# This field contains the Stream ID of a child object. If there is 
		# no child object, then the field MUST be set to NOSTREAM (0xFFFFFFFF).
		Child_ID = ''		# LENGTH: 4 bytes
	
		# This field contains an object class GUID, if this entry is a storage 
		# or root storage. If there is no object class GUID set on this object, 
		# then the field MUST be set to all zeroes. In a stream object, this 
		# field MUST be set to all zeroes. If not NULL, the object class GUID 
		# can be used as a parameter to launch applications.
		CLSID = ''		# LENGTH: 16 bytes

		# This field contains the user-defined flags if this entry is a 
		# storage object or root storage object. If there are no state bits 
		# set on the object, then this field MUST be set to all zeroes.
		State_Bits = ''		# LENGTH: 4 bytes 

		# This field contains the creation time for a storage object. The 
		# Windows FILETIME structure is used to represent this field in UTC. 
		# If there is no creation time set on the object, this field MUST be 
		# all zeroes. For a root storage object, this field MUST be all zeroes, 
		# and the creation time is retrieved or set on the compound file itself.
		Creation_Time = '' 	# LENGTH: 8 bytes
		
		# This field contains the modification time for a storage object. The 
		# Windows FILETIME structure is used to represent this field in UTC. 
		# If there is no modified time set on the object, this field MUST be 
		# all zeroes. For a root storage object, this field MUST be all zeroes, 
		# and the modified time is retrieved or set on the compound file itself.
		Modified_Time = ''	# LENGTH: 8 bytes

		# This field contains the first sector location if this is a stream 
		# object. For a root storage object, this field MUST contain the first 
		# sector of the mini stream, if the mini stream exists.
		Starting_Sector_Location = '' 	# LENGTH 4 bytes
		
		# This 64-bit integer field contains the size of the user-defined data, 
		# if this is a stream object. For a root storage object, this field 
		# contains the size of the mini stream.
		Stream_Size = ''	# LENGTH: 8 bytes


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
		# The LinkFlags structure defines bits that specify which shell link 
		# structures are present in the file format after the ShellLinkHeader 
		# structure (section 2.1). 
		
		# Case for index if value at index is set.
		switch(LinkFlagStructure) {
 			case 0:
    				printf("A");
    				break;
  			case 1:
    				printf("B");
    				break;
  			case 2:
    				printf("C");
    				break;
  			case 3:
    				printf("D");
    				break;
  			case 4:
    				printf("E");
    				break;
  			case 5:
    				printf("F");
    				break;
  			case 6:
    				printf("G");
    				break;
  			case 7:
    				printf("H");
    				break;
  			case 8:
    				printf("I");
    				break;
    			case 9:	
				printf("J");
    				break;
			case 10:
    				printf("K");
    				break;
			case 11:
    				printf("L");
    				break;
			case 12:
    				printf("M");
    				break;
			case 13:
    				printf("N");
    				break;
			case 14:
    				printf("O");
    				break;
			case 15:
    				printf("P");
    				break;
			case 16:
    				printf("Q");
    				break;
			case 17:
    				printf("R");
    				break;
			case 18:
    				printf("S");
    				break;
			case 19:
    				printf("T");
    				break;
			case 20:
    				printf("U");
    				break;
			case 21:
    				printf("V");
    				break;
			case 22:
    				printf("W");
    				break;
			case 23:
    				printf("X");
    				break;
			case 24:
    				printf("Y");
    				break;
			case 25:
    				printf("Z");
    				break;
			case 26:
    				printf("AA");
    				break;
			case 27:
    				printf("0");
    				break;
			case 28:
    				printf("0");
    				break;
			case 29:
    				printf("0");
    				break;
			case 30:
    				printf("0");
    				break;
			case 31:
    				printf("0");
    				break;
  			default:
    				printf("ERROR!");
    				break;
		}

		# Meaning of value
		switch(LinkFlag) {
		 	case A:
			# The shell link is saved with an item ID list (IDList). If this 
			# bit is set, a LinkTargetIDList structure (section 2.2) MUST 
			# follow the ShellLinkHeader .
    				printf("HasLinkTargetIDList");
    				break;
  			case B:
			# The shell link is saved with link information. If this bit is 
			# set, a LinkInfo structure (section 2.3) MUST be present.
    				printf("HasLinkInfo");
    				break;
  			case C:
			# The shell link is saved with a name string. If this bit is set,
			# a NAME_STRING StringData structure (section 2.4) MUST be present.
    				printf("HasName");
    				break;
  			case D:
			# The shell link is saved with a relative path string. If this bit
			# is set, a RELATIVE_PATH StringData structure (section 2.4) MUST 
			# be present.
    				printf("HasRelativePath");
    				break;
  			case E:
			# The shell link is saved with a working directory string. If this
			# bit is set, a WORKING_DIR StringData structure (section 2.4) MUST
			# be present.
    				printf("HasWorkingDir");
    				break;
  			case F:
			# The shell link is saved with command line arguments. If this bit
			# is set, a COMMAND_LINE_ARGUMENTS StringData structure 
			# (section 2.4) MUST be present.
    				printf("HasArguments");
    				break;
  			case G:
			# The shell link is saved with an icon location string. If this bit
			# is set, an ICON_LOCATION StringData structure (section 2.4) MUST 
			# be present.
    				printf("HasIconLocation");
    				break;
  			case H:
			# The shell link contains Unicode encoded strings. This bit SHOULD 
			# be set.
    				printf("IsUnicode");
    				break;
  			case I:
			# The LinkInfo structure (section 2.3) is ignored.
    				printf("ForceNoLinkInfo");
    				break;
    			case J:	
			# The shell link is saved with an EnvironmentVariableDataBlock
			# (section 2.5.4).
				printf("HasExpString");
    				break;
			case K:
    			# The target is run in a separate virtual machine when launching 
			# a link target that is a 16-bit application.
				printf("RunInSeparateProcess");
    				break;
			case L:
			# A bit that is undefined and MUST be ignored.
    				printf("Unused1");
    				break;
			case M:
			# The shell link is saved with a DarwinDataBlock (section 2.5.3).
    				printf("HasDarwinID");
    				break;
			case N:
			# The application is run as a different user when the target of 
			# the shell link is activated.
    				printf("RunAsUser");
    				break;
			case O:
			# The shell link is saved with an IconEnvironmentDataBlock 
			# (section 2.5.5).
    				printf("HasExpIcon");
    				break;
			case P:
			# The file system location is represented in the shell namespace
			# when the path to an item is parsed into an IDList.
    				printf("NoPidAlias");
    				break;
			case Q:
			# A bit that is undefined and MUST be ignored
    				printf("Unused2");
    				break;
			case R:
			# The shell link is saved with a ShimDataBlock (section 2.5.8).
    				printf("RunWithShimLayer");
    				break;
			case S:
			# The TrackerDataBlock (section 2.5.10) is ignored.	
    				printf(" ForceNoLinkTrack");
    				break;
			case T:
			# The shell link attempts to collect target properties and store
			# them in the PropertyStoreDataBlock (section 2.5.7) when the 
			# link target is set.
    				printf("EnableTargetMetadata");
    				break;
			case U:
			# The EnvironmentVariableDataBlock is ignored.
    				printf("DisableLinkPathTracking");
    				break;
			case V:
			# The SpecialFolderDataBlock (section 2.5.9) and the
			# KnownFolderDataBlock (section 2.5.6) are ignored when loading the
			# shell link. If this bit is set, these extra data blocks SHOULD 
			# NOT be saved when saving the shell link.
    				printf("DisableKnownFolderTracking");
    				break;
			case W:
			# If the link has a KnownFolderDataBlock (section 2.5.6), the 
			# unaliased form of the known folder IDList SHOULD be used when
			# translating the target IDList at the time that the link is loaded.
    				printf("DisableKnownFolderAlias");
    				break;
			case X:
			# Creating a link that references another link is enabled. 
			# Otherwise, specifying a link as the target IDList SHOULD NOT be
			# allowed.
    				printf("AllowLinkToLink");
    				break;
			case Y:
			# When saving a link for which the target IDList is under a known 
			# folder, either the unaliased form of that known folder or the 
			# target IDList SHOULD be used.
    				printf("UnaliasOnSave");
    				break;
			case Z:
			# The target IDList SHOULD NOT be stored; instead, the path
			# specified in the EnvironmentVariableDataBlock (section 2.5.4)
			# SHOULD be used to refer to the target.
    				printf("PreferEnvironmentPath");
    				break;
			case AA:
    			# When the target is a UNC name that refers to a location on a 
			# local machine, the local path IDList in the 
			# PropertyStoreDataBlock (section 2.5.7) SHOULD be stored, so it 
			# can be used when the link is loaded on the local machine.
				printf("KeepLocalIDListForUNCTarget");
    				break;
    			default:
				printf("ERROR!");
				break;
		}
		

		


		# 2.1.2 FileAttributesFlags #
		# The FileAttributesFlags structure defines bits that specify the file 
		# attributes of the link target, if the target is a file system item. 
		# File attributes can be used if the link target is not available, or if
		# accessing the target would be inefficient. It is possible for the target 
		# items attributes to be out of sync with this value.
			switch(FileAttributesFlagStructure) {
 			case 0:
    				printf("A");
    				break;
  			case 1:
    				printf("B");
    				break;
  			case 2:
    				printf("C");
    				break;
  			case 3:
    				printf("D");
    				break;
  			case 4:
    				printf("E");
    				break;
  			case 5:
    				printf("F");
    				break;
  			case 6:
    				printf("G");
    				break;
  			case 7:
    				printf("H");
    				break;
  			case 8:
    				printf("I");
    				break;
    			case 9:	
				printf("J");
    				break;
			case 10:
    				printf("K");
    				break;
			case 11:
    				printf("L");
    				break;
			case 12:
    				printf("M");
    				break;
			case 13:
    				printf("N");
    				break;
			case 14:
    				printf("O");
    				break;
			case 15:
    				printf("0");
    				break;
			case 16:
    				printf("0");
    				break;
			case 17:
    				printf("0");
    				break;
			case 18:
    				printf("0");
    				break;
			case 19:
    				printf("0");
    				break;
			case 20:
    				printf("0");
    				break;
			case 21:
    				printf("0");
    				break;
			case 22:
    				printf("0");
    				break;
			case 23:
    				printf("0");
    				break;
			case 24:
    				printf("0");
    				break;
			case 25:
    				printf("0");
    				break;
			case 26:
    				printf("0");
    				break;
			case 27:
    				printf("0");
    				break;
			case 28:
    				printf("0");
    				break;
			case 29:
    				printf("0");
    				break;
			case 30:
    				printf("0");
    				break;
			case 31:
    				printf("0");
    				break;
  			default:
    				printf("ERROR!");
    				break;
		}



		# Meaning of values
		switch(FileAttributesFlagStructure) {
 			case A:
			# The file or directory is read-only. For a file, if this bit is
			# set, applications can read the file but cannot write
    				printf("FILE_ATTRIBUTE_READONLY");
    				break;
  			case B:
			# The file or directory is hidden. If this bit is set, the file or
			# folder is not included in an ordinary directory listing.
    				printf("FILE_ATTRIBUTE_HIDDEN");
    				break;
  			case C:
			# The file or directory is part of the operating system or is used
			# exclusively by the operating system.

    				printf("FILE_ATTRIBUTE_SYSTEM");
    				break;
  			case D:
			# A bit that MUST be zero.
		    				printf("Reserved1");
    				break;
  			case E:
			# The link target is a directory instead of a file.
    				printf("FILE_ATTRIBUTE_DIRECTORY");
    				break;
  			case F:
			# The file or directory is an archive file. Applications use this
			# flag to mark files for backup or removal.
    				printf("FILE_ATTRIBUTE_ARCHIVE");
    				break;
  			case G:
			# A bit that MUST be zero.
    				printf("Reserved2");
    				break;
  			case H:
			# The file or directory has no other flags set. If this bit is 1,
			# all other bits in this structure MUST be clear.
    				printf("FILE_ATTRIBUTE_NORMAL");
    				break;
  			case I:
			# The file is being used for temporary storage.
    				printf("FILE_ATTRIBUTE_TEMPORARY");
    				break;
    			case J:	
			# The file is a sparse file.
				printf("FILE_ATTRIBUTE_SPARSE_FILE");
    				break;
			case K:
			# The file or directory has an associated reparse point.
    				printf("FILE_ATTRIBUTE_REPARSE_POINT");
    				break;
			case L:
			# The file or directory is compressed. For a file, this means that
			# all data in the file is compressed. For a directory, this means
			# that compression is the default for newly created files and
			# subdirectories.
    				printf("FILE_ATTRIBUTE_COMPRESSED");
    				break;
			case M:
			# The data of the file is not immediately available.
    				printf("FILE_ATTRIBUTE_OFFLINE");
    				break;
			case N:
			# The contents of the file need to be indexed.
    				printf("FILE_ATTRIBUTE_NOT_CONTENT_INDEXED");
    				break;
			case O:
			# The file or directory is encrypted. For a file, this means that
			# all data in the file is encrypted. For a directory, this means
			# that encryption is the default for newly created files and
			# subdirectories.
				printf("FILE_ATTRIBUTE_ENCRYPTED")
				break;
		}
		

	

		# 2.1.3 HotKeyFlags
		# The HotKeyFlags structure specifies input generated by a combination
		# of keyboard keys being pressed.
		
		# LowByte (1 byte) 0-7bit contains virtual key code to a key on the keyboard
		# This value MUST be one of the following:
		switch(LowByte){		
			case 0x30:
				printf("0 key")
				break:
			case 0x31:
				printf("1 key")
				break:
			case 0x32:
				printf("2 key")
				break;
			case 0x33:
				printf("3 key")
				break;
			case 0x34:
				printf("4 key")
				break;
			case 0x35:
				printf("5 key")
				break;
			case 0x36:
				printf("6 key")
				break;
			case 0x37:
				printf("7 key")
				break;
			case 0x38:
				printf("8 key")
				break;
			case 0x39:
				printf("9 key")
				break;
			case 0x41:
				printf("A key")
				break;
			case 0x42:
				printf("B key")
				break;
			case 0x43:
				printf("C key")
				break;
			case 0x44:
				printf("D key")
				break;
			case 0x45:
				printf("E key")
				break;
			case 0x46:
				printf("F key")
				break;
			case 0x47:
				printf("G key")
				break;
			case 0x48:
				printf("H key")
				break;
			case 0x49:
				printf("I key")
				break;
			case 0x4A:
				printf("J key")
				break;
			case 0x4B:
				printf("K key")
				break;
			case 0x4C:
				printf("L key")
				break;
			case 0x4D:
				printf("M key")
				break;
			case 0x4E:
				printf("N key")
				break;
			case 0x4F:
				printf("O key")
				break;
			case 0x50:
				printf("P key")
				break;
			case 0x51:
				printf("Q key")
				break;
			case 0x52:
				printf("R key")
				break;
			case 0x53: 
				printf("S key")
				break;
			case 0x54:
				printf("T key")
				break;
			case 0x55: 
				printf("U key")
				break;
			case 0x56:
				printf("V key")
				break;
			case 0x57: 
				printf("W key")
				break;
			case 0x58:
				printf("X key")
				break;
			case 0x59:
				printf("Y key")
				break;
			case 0x5A:
				printf("Z key")
				break;
			case 0x70 | VK_F1:
				printf("F1 key")
				break;
			case 0x71 | VK_F2:
				printf("F2 key")
				break;
			case 0x72 | VK_F3:
				printf("F3 key")
				break;
			case 0x73 | VK_F4:
				printf("F4 key")
				break;
			case 0x74 | VK_F5:
				printf("F5 key")
				break;
			case 0x75 | VK_F6:
				printf("F6 key")
				break;
			case 0x76 | VK_F7:
				printf("F7 key")
				break;
			case 0x77 | VK_F8:
				printf("F8 key")
				break;
			case 0x78 | VK_F9:
				printf("F9 key")
				break;
			case VK_F10 | 0x79:
				printf("F10 key")
				break;
			case VK_F11 | 0x7A:
				printf("F11 key")
				break;
			case VK_F12 | 0x7B:
				printf("F12 key")
				break;
			case VK_F13 | 0x7C:
				printf("F13 key")
				break;
			case VK_F14 | 0x7D:
				printf("F14 key")
				break;
			case VK_F15 | 0x7E:
				printf("F15 key")
				break;
			case VK_F16 | 0x7F:
				printf("F16 key")
				break;
			case VK_F17 | 0x80:
				printf("F17 key")
				break;
			case VK_F18 | 0x81:
				printf("F18 key")
				break;
			case VK_F19 | 0x82:
				printf("F19 key")
				break;
			case VK_F20 | 0x83:
				printf("F20 key")
				break;
			case VK_F21 | 0x84:
				printf("F21 key")
				break;
			case VK_F22 | 0x85:
				printf("F22 key")
				break;
			case VK_F23 | 0x86:
				printf("F23 key")
				break;
			case VK_F24 | 0x87:
				printf("F24 key")
				break;
			case VK_NUMLOCK | 0x90:
				printf("NUM LOCK key")
				break;
			case VK_SCROLL | 0x91:
				printf("SCROLL LOCK key")
				break;
			case HOTKEYF_SHIFT | 0x01:
				printf("The SHIFT key on the keyboard.")
				break;
			case HOTKEYF_CONTROL | 0x02:
				printf("The CTRL key on the keyboard.")
				break;
			case HOTKEYF_ALT | 0x04:
				printf("The ALT key on the keyboard.")
				break;
			default:
				break;
		}

		



		# 2.2 LinkTargetIDList #
		# The LinkTargetIDList structure specifies the target of the link. The 
		# presence of this optional structure is specified by the 
		# HasLinkTargetIDList bit (LinkFlags section 2.1.1) in the ShellLinkHeader 
		# (section 2.1).
		
		# IDListSize (2 bytes): The size, in bytes, of the IDList field.
		IDListSize = ''

		# IDList (variable): A stored IDList structure (section 2.2.1), which 
		# contains the item ID list. An IDList structure conforms to the following 
		# ABNF [RFC5234]:
		IDList = ''
		
		


		# 2.2.1 IDList #
		
		# ItemIDList (variable): An array of zero or more ItemID structures
		# (section 2.2.2).
		ItemIDList = ''

		# TerminalID (2 bytes): A 16-bit, unsigned integer that indicates the end 
		# of the item IDs. This ￼￼value MUST be zero.
		TerminalID = ''



		
		# 2.3 LinkInfo #
		# The LinkInfo structure specifies information necessary to resolve a link
		# target if it is not found in its original location. This includes 
		# information about the volume that the target was stored on, the mapped
		# drive letter, and a Universal Naming Convention (UNC) form of the path if
		# one existed when the link was created. For more details about UNC paths,
		# see [MS-DFSNM] section 2.2.1.4.
		
		# LinkInfoSize (4 bytes): A 32-bit, unsigned integer that specifies the 
		# size, in bytes, of the LinkInfo structure. All offsets specified in this
		# structure MUST be less than this value, and all strings contained in this
		# structure MUST fit within the extent defined by this size.
		LinkInfoSize = ''

		# LinkInfoHeaderSize (4 bytes): A 32-bit, unsigned integer that specifies
		# the size, in bytes, of the LinkInfo header section, which includes all
		# specified offsets. This value MUST be defined as shown in the following
		# table, and it MUST be less than LinkInfoSize.<1>
		LinkInfoHeaderSize = ''
		if (LinkInfoHeaderSize == 0x0000001C):
			printf("Offsets to the optional fields are not specified.")
		elif (0x00000024 ≤ LinkInfoHeaderSize):
				printf("Offsets to the optional fields are specified.")
		
		# LinkInfoFlags (4 bytes): Flags that specify whether the VolumeID,
		# LocalBasePath, LocalBasePathUnicode, and CommonNetworkRelativeLink
		# fields are present in this structure.
		LinkInfoFlags = ''
		switch(LinkedInfoLagsIndex){
			case 0:
				printf("A")
				break;
			case 1:
				printf("B")
				break;
		}
		switch(LinkInfoFlags){
			case A:
			# If set, the VolumeID and LocalBasePath fields are present, and
			# their locations are specified by the values of the VolumeIDOffset
			# and LocalBasePathOffset fields, respectively. If the value of the
			# LinkInfoHeaderSize field is greater than or equal to 0x00000024,
			# the LocalBasePathUnicode field is present, and its location is
			# specified by the value of the LocalBasePathOffsetUnicode field.
			# If not set, the VolumeID, LocalBasePath, and LocalBasePathUnicode 
			# fields are not present, and the values of the VolumeIDOffset and 
			# LocalBasePathOffset fields are zero. If the value of the 
			# LinkInfoHeaderSize field is greater than or equal to 0x00000024,
			# the value of the LocalBasePathOffsetUnicode field is zero.
				printf("VolumeIDAndLocalBasePath")
				break;
			case B:
			# If set, the CommonNetworkRelativeLink field is present, and its
			# location is specified by the value of the 
			# CommonNetworkRelativeLinkOffset field.
			# If not set, the CommonNetworkRelativeLink field is not present,
			# and the value of the CommonNetworkRelativeLinkOffset field is zero.
				printf("CommonNetworkRelativeLinkAndPathSuffix")
				break;
		}

		# VolumeIDOffset (4 bytes): A 32-bit, unsigned integer that specifies the
		# location of the VolumeID field. If the VolumeIDAndLocalBasePath flag is
		# set, this value is an offset, in bytes, from the start of the LinkInfo
		# structure; otherwise, this value MUST be zero.	
		VolumeIDOffset = ''
		
		# LocalBasePathOffset (4 bytes): A 32-bit, unsigned integer that specifies
		# the location of the LocalBasePath field. If the VolumeIDAndLocalBasePath
		# flag is set, this value is an offset, in bytes, from the start of the
		# LinkInfo structure; otherwise, this value MUST be zero.
		LocalBasePathOffset = ''

		# CommonNetworkRelativeLinkOffset (4 bytes): A 32-bit, unsigned integer
		# that specifies the location of the CommonNetworkRelativeLink field. If
		# the CommonNetworkRelativeLinkAndPathSuffix flag is set, this value is an
		# offset, in bytes, from the start of the LinkInfo structure; otherwise,
		# this value MUST be zero.
		CommonNetworkRelativeLinkOffset = ''

		# CommonPathSuffixOffset (4 bytes): A 32-bit, unsigned integer that
		# specifies the location of the CommonPathSuffix field. This value is an 
		# offset, in bytes, from the start of the LinkInfo structure.
		CommonPathSuffixOffset = ''

		# LocalBasePathOffsetUnicode (4 bytes): An optional, 32-bit, unsigned
		# integer that specifies the location of the LocalBasePathUnicode field.
		# If the VolumeIDAndLocalBasePath flag is set, this value is an offset,
		# in bytes, from the start of the LinkInfo structure; otherwise, this value
		# MUST be zero. This field can be present only if the value of the
		# LinkInfoHeaderSize field is greater than or equal to 0x00000024.
		LocalBasePathOffsetUnicode = ''

		# CommonPathSuffixOffsetUnicode (4 bytes): An optional, 32-bit, unsigned
		# integer that specifies the location of the CommonPathSuffixUnicode field.
		# This value is an offset, in bytes, from the start of the LinkInfo
		# structure. This field can be present only if the value of the
		# LinkInfoHeaderSize field is greater than or equal to 0x00000024.
		CommonPathSuffixOffsetUnicode = ''		

		# VolumeID (variable): An optional VolumeID structure (section 2.3.1) 
		# that specifies information about the volume that the link target was on
		# when the link was created. This field is present if the
		# VolumeIDAndLocalBasePath flag is set.
		VolumeID = ''

		# LocalBasePath(variable): Anoptional,NULL–terminatedstring,
		# definedbythesystemdefault code page, which is used to construct the full
		# path to the link item or link target by appending the string in the
		# CommonPathSuffix field. This field is present if the
		# VolumeIDAndLocalBasePath flag is set.
		LocalBasePath = ''
		
		# CommonNetworkRelativeLink (variable): An optional
		# CommonNetworkRelativeLink structure (section 2.3.2) that specifies
		# information about the network location where the link target is stored.
		CommonNetworkRelativeLink = ''

		# CommonPathSuffix (variable): A NULL–terminated string, defined by the
		# system default code page, which is used to construct the full path to the
		# link item or link target by being appended to the string in the
		# LocalBasePath field.
		CommonPathSuffix = ''

		
		# LocalBasePathUnicode (variable): An optional, NULL–terminated, Unicode
		# string that is used to construct the full path to the link item or link
		# target by appending the string in the CommonPathSuffixUnicode field. This
		# field can be present only if the VolumeIDAndLocalBasePath flag is set and
		# the value of the LinkInfoHeaderSize field is greater than or equal to
		# 0x00000024.
		LocalBasePathUniode = ''

		# CommonPathSuffixUnicode (variable): An optional, NULL–terminated, Unicode
		# string that is used to construct the full path to the link item or link
		# target by being appended to the string in the LocalBasePathUnicode field.
		# This field can be present only if the value of the LinkInfoHeaderSize
		# field is greater than or equal to 0x00000024.
		CommonPathSuffixUnicode = ''

		



		# 2.3.1 VolumeID #
		# The VolumeID structure specifies information about the volume that a 
		# link target was on when the link was created. This information is useful
		# for resolving the link if the file is not found in its original location.
	
		# VolumeIDSize (4 bytes): A 32-bit, unsigned integer that specifies the 
		# size, in bytes, of this structure. This value MUST be greater than
		# 0x00000010. All offsets specified in this structure MUST be less than
		# this value, and all strings contained in this structure MUST fit within
		# the extent defined by this size.
		VolumeIDSize = ''
		
		# DriveType (4 bytes): A 32-bit, unsigned integer that specifies the type
		# of drive the link target is stored on. This value MUST be one of the
		# following:
		DriveType = ''
		switch(DriveType){
			case DRIVE_UNKNOWN | 0x00000000:
				printf("The drive type cannot be determined.")
				break;
			case DRIVE_NO_ROOT_DIR | 0x00000001:
				printf("The root path is invalid; for example, there" \
				" is no volume mounted at the path.")
				break;
			case DRIVE_REMOVABLE| 0x00000002:
				printf("The drive has removable media, such as a"\
				" floppy drive, thumb drive, or flash card reader.")
				break;
			case DRIVE_FIXED | 0x00000003:
				printf("The drive has fixed media, such as a hard"\
				" drive or flash drive.")
				break;
			case DRIVE_REMOTE | 0x00000004:
				printf("The drive is a remote (network) drive.")
				break;
			case DRIVE_CDROM | 0x00000005:
				printf("The drive is a CD-ROM drive.")
				break;
			case DRIVE_RAMDISK | 0x00000006:
				break;
		}

		# DriveSerialNumber (4 bytes): A 32-bit, unsigned integer that specifies
		# the drive serial number of the volume the link target is stored on.
		DriveSerialNumber = ''

		# VolumeLabelOffset (4 bytes): A 32-bit, unsigned integer that specifies
		# the location of a string that contains the volume label of the drive that
		# the link target is stored on. This value is an offset, in bytes, from the
		# start of the VolumeID structure to a NULL-terminated string of characters,
		# defined by the system default code page. The volume label string is 
		# located in the Data field of this structure.
		VolumeLabelOffset = ''
		# If the value of this field is 0x00000014, it MUST be ignored, and the 
		# value of the VolumeLabelOffsetUnicode field MUST be used to locate the
		# volume label string.
	

		# VolumeLabelOffsetUnicode (4 bytes): An optional, 32-bit, unsigned 
		# integer that specifies the location of a string that contains the
		# volume label of the drive that the link target is stored on. This value
		# is an offset, in bytes, from the start of the VolumeID structure to a
		# NULL- terminated string of Unicode characters. The volume label string is
		# located in the Data field of this structure.
		VolumeLabelOffsetUnicode = ''
		# If the value of the VolumeLabelOffset field is not 0x00000014, this 
		# field MUST be ignored, and the value of the VolumeLabelOffset field MUST
		# be used to locate the volume label string.
		
		# Data (variable): A buffer of data that contains the volume label of the
		# drive as a string defined by the system default code page or Unicode
		# characters, as specified by preceding fields.
		Data = ''

		



		# 2.3.2 CommonNetworkRelativeLink # 
		# The CommonNetworkRelativeLink structure specifies information about the
		# network location where a link target is stored, including the mapped
		# drive letter and the UNC path prefix. For details on UNC paths, see
		# [MS-DFSNM] section 2.2.1.4.
		
		# CommonNetworkRelativeLinkSize (4 bytes): A 32-bit, unsigned integer that
		# specifies the size, in bytes, of the CommonNetworkRelativeLink structure.
		# This value MUST be greater than or equal to 0x00000014. All offsets
		# specified in this structure MUST be less than this value, and all strings
		# contained in this structure MUST fit within the extent defined by this
		# size.
		CommonNetworkRelativeLinkSize = ''

		# CommonNetworkRelativeLinkFlags (4 bytes): Flags that specify the 
		# contents of the DeviceNameOffset and NetProviderType fields.
		CommonNetworkRelativeLinkFlags = ''
		switch(CommonNetworkRelativeLinkFlags){
			case A | ValidNetType:
				printf("If set, the DeviceNameOffset field contains an"\
				" offset to the device name."\
				" If not set, the DeviceNameOffset field does not contain"\
				" an offset to the device name, and its value MUST be zero.")
				break;
			case B | ValidNetType:
				printf("If set, the NetProviderType field contains the "\
				"network provider type. If not set, the NetProviderType "\
				"field does not contain the network provider type, and its"\
				" value MUST be zero.")
				break;
		
		# NetNameOffset (4 bytes): A 32-bit, unsigned integer that specifies the
		# location of the NetName field. This value is an offset, in bytes, from
		# the start of the CommonNetworkRelativeLink structure.
		NetNameOffset = ''

		# DeviceNameOffset (4 bytes): A 32-bit, unsigned integer that specifies
		# the location of the DeviceName field. If the ValidDevice flag is set,
		# this value is an offset, in bytes, from the start of the
		# CommonNetworkRelativeLink structure; otherwise, this value MUST be zero.
		DeviceNameOffset = ''
					
		# NetworkProviderType (4 bytes): A 32-bit, unsigned integer that specifies
		# the type of network provider. If the ValidNetType flag is set, this 
		# value MUST be one of the following; otherwise, this value MUST be ignored.
		NetworkProviderType = ''
		switch(NetworkProviderType){
			case 0x001A0000:
				printf("WNNC_NET_AVID")
				break;
			case 0x001B0000:
				printf("WNNC_NET_DOCUSPACE")
				break;
			case 0x001C0000:
				printf("WNNC_NET_MANGOSOFT")
				break;
			case 0x001D0000:
				printf("WNNC_NET_SERNET")
				break;
			case 0X001E0000:
				printf("WNNC_NET_RIVERFRONT1")
				break;
			case 0x001F0000:
				printf("WNNC_NET_RIVERFRONT2")
				break;
			case 0x00200000:
				printf("WNNC_NET_DECORB")
				break;
			case 0x00210000:
				printf("WNNC_NET_PROTSTOR")
				break;
			case 0x00220000:
				printf("WNNC_NET_FJ_REDIR")
				break;
			case 0x00230000:
				printf("WNNC_NET_DISTINCT")
				break;
			case 0x00240000:
				printf("WNNC_NET_TWINS")
				break;
			case 0x00250000:
				printf("WNNC_NET_RDR2SAMPLE")
				break;
			case 0x00260000:
				printf("WNNC_NET_CSC")
				break;
			case 0x00270000:
				printf("WNNC_NET_3IN1")
				break;
			case 0x00290000:
				printf("WNNC_NET_EXTENDNET")
				break;
			case 0x002A0000:
				printf"(WNNC_NET_STAC")			
				break;
			case 0x002B0000:
				printf("WNNC_NET_FOXBAT")
				break;
			case￼ 0x002C0000:
				printf("WNNC_NET_YAHOO") 
			case 0x002D0000:
				printf("WNNC_NET_EXIFS")
			case￼ 0x002E0000:
				printf("WNNC_NET_DAV")
			case￼ 0x002F0000:
				printf("WNNC_NET_KNOWARE")
			case￼ 0x00300000:
				printf("WNNC_NET_OBJECT_DIRE")
			case￼ 0x00310000:
				printf("WNNC_NET_MASFAX")
			case 0x00320000:
				printf("WNNC_NET_HOB_NFS")
			case￼ 0x00330000:
				printf("WNNC_NET_SHIVA")
			case￼ 0x00340000:
				printf("WNNC_NET_IBMAL")
			case￼ 0x00350000:
				printf("WNNC_NET_LOCK")
			case 0x00360000:
				printf("WNNC_NET_TERMSRV")
			case￼ 0x00370000:
				printf("WNNC_NET_SRT")
			case￼ 0x00380000:
				printf("WNNC_NET_QUINCY")
			case 0x00390000:
				printf("WNNC_NET_OPENAFS")
			case￼ 0X003A0000:
				printf("WNNC_NET_AVID1")
			case￼ 0x003B0000:
				printf("WNNC_NET_DFS")
			case￼ 0x003C0000:
				printf("WNNC_NET_KWNP")
			case 0x003D0000:
				printf("WNNC_NET_ZENWORKS")
			case￼ 0x003E0000:
				printf("WNNC_NET_DRIVEONWEB")
			case￼ 0x003F0000:
				printf("WNNC_NET_VMWARE")
			case￼ 0x00400000:
				printf("WNNC_NET_RSFX")
			case￼ 0x00410000:
				printf("WNNC_NET_MFILES")
			case￼ 0x00420000:
				printf("WNNC_NET_MS_NFS")
			case￼ 0x00430000:
				printf("WNNC_NET_GOOGLE")

		}
		
		# NetNameOffsetUnicode (4 bytes): An optional, 32-bit, unsigned integer 
		# that specifies the location of the NetNameUnicode field. This value is
		# an offset, in bytes, from the start of the CommonNetworkRelativeLink 
		# structure. This field MUST be present if the value of the NetNameOffset 
		# field is greater than 0x00000014; otherwise, this field MUST NOT be
		# present.
		NetNameOffsetUnicode = ''

		# DeviceNameOffsetUnicode (4 bytes): An optional, 32-bit, unsigned 
		# integer that specifies the location of the DeviceNameUnicode field.
		# This value is an offset, in bytes, from the start of the
		# CommonNetworkRelativeLink structure. This field MUST be present if the
		# value of the NetNameOffset field is greater than 0x00000014; otherwise,
		# this field MUST NOT be present.	
		DeviceNameOffsetUnicode = ''	
	
		# NetName (variable): ANULL–terminated string, as defined by the system 
		# default code page, which specifies a server share path; for example,
		# "\\server\share".
		NetName = ''

		# DeviceName (variable): A NULL–terminated string, as defined by the
		# system default code page, which specifies a device; for example, the
		# drive letter "D:".
		DeviceName = ''

		# NetNameUnicode (variable): An optional, NULL–terminated, Unicode string
		# that is the Unicode version of the NetName string. This field MUST be
		# present if the value of the NetNameOffset field is greater than
		# 0x00000014; otherwise, this field MUST NOT be present.
		NetNameUnicode = ''

		# DeviceNameUnicode (variable): An optional, NULL–terminated, Unicode
		# string that is the Unicode version of the DeviceName string. This field
		# MUST be present if the value of the NetNameOffset field is greater than
		# 0x00000014; otherwise, this field MUST NOT be present.
		DeviceNameUnicode = ''

		


		

		# 2.4 StringData #
	
		# StringData refers to a set of structures that convey user interface and
		# path identification information. The presence of these optional
		# structures is controlled by LinkFlags (section 2.1.1) in the
		# ShellLinkHeader (section 2.1).
		# The StringData structures conform to the following ABNF rules [RFC5234].
		# STRING_DATA = [NAME_STRING] [RELATIVE_PATH] [WORKING_DIR] 
		# [COMMAND_LINE_ARGUMENTS] [ICON_LOCATION]

		# NAME_STRING: An optional structure that specifies a description of the
		# shortcut that is displayed to end users to identify the purpose of the
		# shell link. This structure MUST be present if the HasName flag is set.
		NAME_STRING = ''

		# RELATIVE_PATH: An optional structure that specifies the location of the
		# link target relative to the file that contains the shell link. When
		# specified, this string SHOULD be used when resolving the link. This
		# structure MUST be present if the HasRelativePath flag is set.
		RELATIVE_PATH = ''

		# WORKING_DIR: An optional structure that specifies the file system path
		# of the working directory to be used when activating the link target.
		# This structure MUST be present if the HasWorkingDir flag is set.
		WORKING_DIR = ''

		# COMMAND_LINE_ARGUMENTS: An optional structure that stores the 
		# command-line arguments that should be specified when activating the 
		# link target. This structure MUST be present if the HasArguments flag 
		# is set.
		COMMAND_LINE_ARGUMENTS = ''

		# ICON_LOCATION: An optional structure that specifies the location of
		# the icon to be used when displaying a shell link item in an icon view.
		# This structure MUST be present if the HasIconLocation flag is set.
		ICON_LOCATION = ''

		# CountCharacters (2 bytes): A 16-bit, unsigned integer that specifies
		# either the number of characters, defined by the system default code
		# page, or the number of Unicode characters found in the String field.
		# A value of zero specifies an empty string.
		CountCharacters = ''

		# All StringData structures have the following structure:
		# bits 0 -> 15 : CountCharacters
		# bits 16 ->21 : String (variable)

		# String (variable): An optional set of characters, defined by the system
		# default code page, or a Unicode string with a length specified by the
		# CountCharacters field. This string MUST NOT be NULL-terminated.
		String  = ''
	
		


		
		# 2.5 ExtraData # 

		# ExtraData refers to a set of structures that convey additional 
		# information about a link target. These optional structures can be 
		# present in an extra data section that is appended to the basic Shell
		# Link Binary File Format.
		# The ExtraData structures conform to the following ABNF rules [RFC5234]:
		
		# EXTRA_DATA = *EXTRA_DATA_BLOCK TERMINAL_BLOCK

		# EXTRA_DATA_BLOCK = CONSOLE_PROPS / CONSOLE_FE_PROPS / DARWIN_PROPS
		# / ENVIRONMENT_PROPS / ICON_ENVIRONMENT_PROPS / KNOWN_FOLDER_PROPS 
		# / PROPERTY_STORE_PROPS / SHIM_PROPS / SPECIAL_FOLDER_PROPS 
		# / TRACKER_PROPS / VISTA_AND_ABOVE_IDLIST_PROPS
￼￼￼
		# EXTRA_DATA: A structure consisting of zero or more property data blocks
		# followed by a terminal block.
		EXTRA_DATA = ''

		# EXTRA_DATA_BLOCK: A structure consisting of any one of the following
		# property data blocks. 
		EXTRA_DATA_BLOCK = ''
		# CONSOLE_PROPS: A ConsoleDataBlock structure (section 2.5.1).
		# CONSOLE_FE_PROPS: A ConsoleFEDataBlock structure (section 2.5.2). 
		# DARWIN_PROPS: A DarwinDataBlock structure (section 2.5.3). 
		# ENVIRONMENT_PROPS: An EnvironmentVariableDataBlock structure 
		# (section 2.5.4).
		# ICON_ENVIRONMENT_PROPS: An IconEnvironmentDataBlock structure 
		# (section 2.5.5).
		# KNOWN_FOLDER_PROPS: A KnownFolderDataBlock structure (section 2.5.6).
		# PROPERTY_STORE_PROPS: A PropertyStoreDataBlock structure (section 2.5.7).
		# SHIM_PROPS: A ShimDataBlock structure (section 2.5.8).
		# SPECIAL_FOLDER_PROPS: A SpecialFolderDataBlock structure (section 2.5.9).
		# TRACKER_PROPS: A TrackerDataBlock structure (section 2.5.10).
		# VISTA_AND_ABOVE_IDLIST_PROPS: A VistaAndAboveIDListDataBlock structure 
		#(section 2.5.11).
		
		# TERMINAL_BLOCK A structure that indicates the end of the extra data
		# section.
		TERMINAL_BLOCK = ''

		# The general structure of an extra data section is shown in the 
		# following diagram.

		# ExtraDataBlock (variable): An optional array of bytes that contains zero 
		# or more property data blocks listed in the EXTRA_DATA_BLOCK syntax rule.
		ExtraDataBlock = ''
		
		# TerminalBlock (4 bytes): A 32-bit, unsigned integer that indicates the 
		# end of the extra data section. This value MUST be less than 0x00000004.
		TerminalBlock = ''

		





		# 2.5.1 ConsoleDataBlock #
		# The ConsoleDataBlock structure specifies the display settings to use 
		# when a link target specifies an application that is run in a console
		# window.
		
		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the size
		# of the ConsoleDataBlock structure. This value MUST be 0x000000CC.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies 
		# the signature of the ConsoleDataBlock extra data section. This value
		# MUST be 0xA0000002.
		BlockSignature = ''

		# FillAttributes (2 bytes): A 16-bit, unsigned integer that specifies the
		# fill attributes that control the foreground and background text colors
		# in the console window. The following bit definitions can be combined to
		# specify 16 different values each for the foreground and background
		# colors:
		FillAttributes = ''
		switch(FileAttributes){		
			case 0x0001:
				printf("FOREGROUND_BLUE")
				# The foreground text color contains blue.
				break;
			case 0x0002:
				printf("FOREGROUND_GREEN")
				#The foreground text color contains green.
				break;
			case 0x0004:
				printf("FOREGROUND_RED")
				# The foreground text color contains red.
				break;
			case 0x0008:
				printf("FOREGROUND_INTENSITY")
				# The foreground text color is intensified.
				break;
			case 0x0010:
				printf("BACKGROUND_BLUE")
				# The background text color contains blue.
				break;
			case 0x0020:
				printf("BACKGROUND_GREEN")
				# The background text color contains green.
				break;
			case 0x0040:
				printf("BACKGROUND_RED")
				# The background text color contains red.
				break;
			case 0x0080:
				printf("BACKGROUND_INTENSITY")
				# The background text color is intensified.
				break;
		}
		
		# PopupFillAttributes (2 bytes): A 16-bit, unsigned integer that 
		# specifies the fill attributes that control the foreground and 
		# background text color in the console window popup. The values are the 
		# same as for the FillAttributes field.
		PopupFillAttributes = ''

		# ScreenBufferSizeX (2 bytes): A 16-bit, signed integer that specifies
		# the horizontal size (X axis), in characters, of the console window buffer.
		ScreenBufferSizeX = ''
		
		# ScreenBufferSizeY (2 bytes): A 16-bit, signed integer that specifies 
		# the vertical size (Y axis), in characters, of the console window buffer.
		ScreenBufferSizeY = ''	
	
		# WindowSizeX (2bytes): A16-bit,signed integer that specifies the
		# horizontal size(Xaxis),in characters, of the console window.
		WindowSizeX = ''

		# WindowSizeY (2 bytes): A 16-bit, signed integer that specifies the
		# vertical size (Y axis), in characters, of the console window.
		
		# WindowOriginX (2 bytes): A 16-bit, signed integer that specifies the
		# horizontal coordinate (X axis), in pixels, of the console window origin.
		WindowOriginX = ''

		# WindowOriginY (2 bytes): A 16-bit, signed integer that specifies the
		# vertical coordinate (Y axis), in pixels, of the console window origin.
		WindowOriginY = ''

		# Unused1 (4 bytes): A value that is undefined and MUST be ignored.
		Unused1 = ''
	
		# Unused2 (4 bytes): A value that is undefined and MUST be ignored.
		Unused2 = ''

		# FontSize (4 bytes): A 32-bit, unsigned integer that specifies the
		# size, in pixels, of the font used in the console window.
		FontSize = ''

		# FontFamily (4 bytes): A 32-bit, unsigned integer that specifies the
		# family of the font used in the console window. This value MUST be one 
		# of the following:
		FontFamily = ''
		switch(FontFamily){
			case FF_DONTCARE | 0x0000:
				printf("The font family is unknown.")
				break;
			case FF_ROMAN | 0x0010:
				printf("The font is variable-width with serifs; for"\ 
				" example, \"Times New Roman\".")
				break;
			case FF_SWISS | 0x0020:
				printf("The font is variable-width without serifs; for "\
				"example, \"Arial\".")
				break;
			case FF_MODERN | 0x0030:
				printf("The font is fixed-width, with or without serifs; "\
				"for example, \"Courier New\".")
				break;
			case FF_SCRIPT | 0x0040:
				printf("The font is designed to look like handwriting; "\
				"for example, \"Cursive\".")
				break;
			case FF_DECORATIVE | 0x0050:
				printf("The font is a novelty font; for example, \"Old "\
				"English\".")
				break;
		}

		# FontWeight (4 bytes): A 16-bit, unsigned integer that specifies the
		# stroke weight of the font used in the console window.
		FontWeight = ''
		if(FontWeight >= 700):
			printf("A bold font.")
		elif(FontWeight < 700):
			printf("A regular-weight font.")
		else
			printf("error")

		# Face Name (64 bytes): A 32-character Unicode string that specifies the
		# face name of the font used in the console window.
		Face Name = ''

		# CursorSize (4 bytes): A 32-bit, unsigned integer that specifies the 
		# size of the cursor, in pixels, used in the console window.
		CursorSize = ''
		if(CursorSize <=25):
			printf("A small cursor.")
		elif(CursorSize >=26) and (CursorSize <=50):
			printf("A medium cursor.")
		elif(CursorSize >= 51) and (CursorSize <= 100):
			printf("A large cursor.")

		# FullScreen (4 bytes): A 32-bit, unsigned integer that specifies whether
		# to open the console window in full-screen mode.
		FullScreen = ''
		if(FullScreen > 0x00000000):
			printf("Full-screen mode is on.")
		elif(FullScreen == 0x00000000):
			printf("Full-screen mode is off.")
		else
			printf("Error: FullScreen value is not valid:" + FullScreen)
		
		# QuickEdit (4 bytes): A 32-bit, unsigned integer that specifies whether
		# to open the console window in QuikEdit mode. In QuickEdit mode, the
		# mouse can be used to cut, copy, and paste text in the console window.
		QuickEdit = ''
		if(QuickEdit > 0x00000000):
			printf("QuickEdit mode is on.")
		elif(QuickEdit == 0x00000000):
			printf("QuickEdit mode is off.")
		else
			printf("Error: QuickEdit value is not valid:" + QuickEdit)
	
		# InsertMode (4 bytes): A 32-bit, unsigned integer that specifies insert
		# mode in the console window.
		InsertMode = ''
		if(InsertMode > 0x00000000):
			printf("InsertMode mode is enabled.")
		elif(InsertMode == 0x00000000):
			printf("InsertMode mode is disabled.")
		else
			printf("Error: InsertMode value is not valid:" + InsertMode)

		
		# AutoPosition (4 bytes): A 32-bit, unsigned integer that specifies 
		# auto-position mode of the console window.
		AutoPosition = ''
		if(AutoPosition > 0x00000000):
			printf("The console window is positioned automatically.")
		elif(AutoPosition == 0x00000000):
			printf("The values of the WindowOriginX and WindowOriginY "\
			"fields are used to position the console window.")
		else
			printf("Error: AutoPosition value is not valid:" + AutoPosition)

		# HistoryBufferSize (4 bytes): A 32-bit, unsigned integer that specifies 
		# the size, in characters, of the buffer that is used to store a 
		# history of user input into the console window.
		HistoryBufferSize = ''

		# NumberOfHistoryBuffers (4 bytes): A 32-bit, unsigned integer that
		# specifies the number of history buffers to use.
		NumberOfHistoryBuffers = ''

		# HistoryNoDup (4 bytes): A 32-bit, unsigned integer that specifies 
		# whether to remove duplicates in the history buffer.
		HistoryNoDup = ''
		if(HistoryNoDup > 0x00000000):
			printf("Duplicates are allowed.")
		elif(HistoryNoDup == 0x00000000):
			printf("Duplicates are not allowed.")
		else
			printf("Error: InsertMode value is not valid:" + InsertMode)

		# ColorTable (64 bytes): A table of 16 32-bit, unsigned integers
		# specifying the RGB colors that are used for text in the console window.
		# The values of the fill attribute fields FillAttributes and 
		# PopupFillAttributes are used as indexes into this table to specify the
		# final foreground and background color for a character.
		ColorTable = ''

		# 2.5.2 ConsoleFEDataBlock #
		
		# The ConsoleFEDataBlock structure specifies the code page to use for
		# displaying text when a link target specifies an application that is run
		# in a console window.

		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the
		# size of the ConsoleFEDataBlock structure. This value MUST be 0x0000000C.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies the
		# signature of the ConsoleFEDataBlock extra data section. This value
		# MUST be 0xA0000004.
		BlockSignature = ''

		# CodePage (4 bytes): A 32-bit, unsigned integer that specifies a code
		# page language code identifier. For details concerning the structure and
		# meaning of language code identifiers, see [MS-LCID]. For additional
		# background information, see [MSCHARSET] and [MSDN- CODEPAGE].
		CodePage = ''



		

		# 2.5.3 DarwinDataBlock #
		
		# The DarwinDataBlock structure specifies an application identifier that
		# can be used instead of a link target IDList to install an application
		# when a shell link is activated.

		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the 
		# size of the DarwinDataBlock structure. This value MUST be 0x00000314.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies
		# the signature of the DarwinDataBlock extra data section. This value 
		# MUST be 0xA0000006.
		BlockSignature = ''
		
		# DarwinDataAnsi (260 bytes): A NULL–terminated string, defined by the 
		# system default code page, which specifies an application identifier. 
		# This field SHOULD be ignored.	
		DarwinDataAnsi = ''

		# DarwinDataUnicode (520 bytes): An optional, NULL–terminated, Unicode
		# string that specifies an application identifier.<4>
		DarwinDataUnicode = ''





		# 2.5.4 EnvironmentVariableDataBlock #

		# The EnvironmentVariableDataBlock structure specifies a path to 
		# environment variable information when the link target refers to a 
		# location that has a corresponding environment variable.
		
		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the 
		# size of the EnvironmentVariableDataBlock structure. This value MUST
		# be 0x00000314.
		BlockSize = ''
				
		# TargetAnsi (260 bytes): A NULL-terminated string, defined by the
		# system default code page, which specifies a path to environment 
		# variable information.
		TargetAnsi = ''

		# TargetUnicode (520 bytes): An optional, NULL-terminated, Unicode 
		# string that specifies a path to environment variable information.
		TargetUnicode = ''

		



		# 2.5.5 IconEnvironmentDataBlock # 

		# The IconEnvironmentDataBlock structure specifies the path to an icon.
		# The path is encoded using environment variables, which makes it 
		# possible to find the icon across machines where the locations vary but
		# are expressed using environment variables.

		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the
		# size of the IconEnvironmentDataBlock structure. This value MUST be
		# 0x00000314.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies
		# the signature of the IconEnvironmentDataBlock extra data section.
		# This value MUST be 0xA0000007.
		BlockSignature = ''

		# TargetAnsi (260 bytes): A NULL-terminated string, defined by the 
		# system default code page, which specifies a path that is constructed
		# with environment variables.
		TargetAnsi = ''
		
		# TargetUnicode (520 bytes): An optional, NULL-terminated, Unicode 
		# string that specifies a path that is constructed with environment
		# variables.
		TargetUnicode = ''





		# 2.5.6 KnownFolderDataBlock #
	
		# The KnownFolderDataBlock structure specifies the location of a known 
		# folder. This data can be used when a link target is a known folder to
		# keep track of the folder so that the link target IDList can be
		# translated when the link is loaded.

		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the 
		# size of the KnownFolderDataBlock structure. This value MUST be
		# 0x0000001C.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies 
		# the signature of the KnownFolderDataBlock extra data section. This value
		# MUST be 0xA000000B.
		BlockSignature = ''

		# KnownFolderID (16 bytes): A value in GUID packet representation 
		# ([MS-DTYP] section 2.3.2.2) that specifies the folder GUID ID.	
		KnownFolderID = ''

		# Offset (4 bytes): A 32-bit, unsigned integer that specifies the
		# location of the ItemID of the first child segment of the IDList
		# specified by KnownFolderID. This value is the offset, in bytes, into
		# the link target IDList.
		Offset = ''






		# 2.5.7 PropertyStoreDataBlock # 
		
		# A PropertyStoreDataBlock structure specifies a set of properties that 
		# can be used by applications to store extra data in the shell link.

		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the size
		# of the PropertyStoreDataBlock structure. This value MUST be greater than
		# or equal to 0x0000000C.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies the
		# signature of the PropertyStoreDataBlock extra data section. This value
		# MUST be 0xA0000009.
		BlockSignature = ''

		# PropertyStore (variable): A serialized property storage structure
		# ([MS-PROPSTORE] section 2.2).
		PropertyStore = ''






		# 2.5.8 ShimDataBlock # 
		
		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the size
		# of the ShimDataBlock structure. This value MUST be greater than or equal
		# to 0x00000088.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies the
		# signature of the ShimDataBlock extra data section. This value MUST be
		# 0xA0000008.
		BlockSignature = ''

		# LayerName (variable): A Unicode string that specifies the name of a shim 
		# layer to apply to a link target when it is being activated.
		LayerName = ''
		
	



		
		
		# 2.5.9 SpecialFolderDataBlock # 
		
		# The SpecialFolderDataBlock structure specifies the location of a special
		# folder. This data can be used when a link target is a special folder to
		# keep track of the folder, so that the link target IDList can be translated
		# when the link is loaded.
		
		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the size 
		# of the SpecialFolderDataBlock structure. This value MUST be 0x00000010.
		BlockSize = ''

		# SpecialFolderID (4 bytes): A 32-bit, unsigned integer that specifies the
		# folder integer ID.
		SpecialFolderID = ''

		# Offset (4 bytes): A 32-bit, unsigned integer that specifies the 
		# location of the ItemID of the first child segment of the IDList specified
		# by SpecialFolderID. This value is the offset, in bytes, into the link
		# target IDList.
		Offset = ''

		


		# 2.5.10 TrackerDataBlock # 
		
		# The TrackerDataBlock structure specifies data that can be used to 
		# resolve a link target if it is not found in its original location when
		# the link is resolved. This data is passed to the Link Tracking service
		# [MS-DLTW] to find the link target.
		
		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the size 
		# of the TrackerDataBlock structure. This value MUST be 0x00000060.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies the
		# signature of the TrackerDataBlock extra data section. This value MUST be
		# 0xA0000003.
		BlockSignature = ''

		# Length (4 bytes): A 32-bit, unsigned integer. This value MUST be greater
		# than or equal to 0x0000058.
		Length = ''

		# Version (4 bytes): A 32-bit, unsigned integer. This value MUST be
		# 0x00000000.
		Version = ''

		# MachineID (variable): A character string, as defined by the system
		# default code page, which specifies the NetBIOS name of the machine where 
		# the link target was last known to reside.
		MachineID = ''

		# Droid (32 bytes): Two values in GUID packet representation ([MS-DTYP]
		# section 2.3.2.2) that are used to find the link target with the Link
		# Tracking service, as specified in [MS-DLTW].
		Droid = ''

		# DroidBirth (32 bytes): Two values in GUID packet representation that 
		# are used to find the link target with the Link Tracking service
		DroidBirth = ''







		# 2.5.11 VistaAndAboveIDListDataBlock # 
		
		# The VistaAndAboveIDListDataBlock structure specifies an alternate IDList
		# that can be used instead of the LinkTargetIDList structure (section 2.2)
		# on platforms that support it.
		
		# BlockSize (4 bytes): A 32-bit, unsigned integer that specifies the size
		# of the VistaAndAboveIDListDataBlock structure. This value MUST be greater
		# than or equal to 0x0000000A.
		BlockSize = ''

		# BlockSignature (4 bytes): A 32-bit, unsigned integer that specifies the
		# signature of the VistaAndAboveIDListDataBlock extra data section. This 
		# value MUST be 0xA000000C.
		BlockSignature = ''

		# IDList (variable): An IDList structure (section 2.2.1).
		IDList = ''


		




	# def DecryptJumpListID():
		# return nameOfJumpList

