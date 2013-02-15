
from vutils import *

def cfb_file_format():
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
