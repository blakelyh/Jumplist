from vutils import *
def cfb_Directory_Entry():

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

