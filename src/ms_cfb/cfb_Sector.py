from vutils import *
def cfb_Sector()
	# 2.1 Compound File Sector Numbers and Types #
	REGSECT	= 0x00000000 - 0xFFFFFFF9	# Regular Sector number
	# REGSECT may need to be broken into regsectLow & regsectHigh
	# due to the range value given.
	
	MAXREGSECT = 0xFFFFFFFA	# Maximum regular sector number
	
	DIFSECT = 0xFFFFFFFC	# Specifies a DIFAT sector in the FAT
	
	FATSECT = 0xFFFFFFFD	# Specifies a FAT sector in the FAT	
	
	ENDOFCHAIN = 0xFFFFFFFE	# End of linked chain of sectors
	
	FREESECT = 0xFFFFFFFF	# Specifies unallocated sector in the 
				# FAT, Mini FAT, or DIFAT
		

