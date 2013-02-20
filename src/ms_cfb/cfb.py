

from vutils import *
class cfb():
	
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
		


 

	def cfb_sector():
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

	def cfb_file_Format():
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
						



	def cfb_header():
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

		


	def cfb_FAT_Sectors():
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
		



	def cfb_mini_FAT_Sectors():
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
		



	def cfb_DIFAT_Sectors():
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




	def cfb_Directory_Sectors():
		# 2.6 Compound File Directory Sectors #
		# The directory entry array is a structure used to contain information 
		# about the stream and storage objects in a compound file, and to 
		# maintain a tree-style containment structure. The directory entry 
		# array is allocated as a standard chain of directory sectors within 
		# the FAT. Each directory entry is identified by a non-negative number 
		# called the stream ID. The first sector of the directory sector chain 
		# MUST contain the root storage directory entry as the first directory 
		# entry at stream ID 0.
		



	def cfb_Directory_Entry():
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

