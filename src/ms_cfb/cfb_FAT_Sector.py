from vutils import *
def cfb_FAT_Sector():

	# 2.3 Compound File FAT Sectors #
	Next_Sector_in_Chain = ''		# LENGTH: variable
	# This field specifies the next sector number in a chain of sectors.
	# If Header Major Version is 3, then there MUST be 128 fields specified 
	# to fill a 512-byte sector.
	# If Header Major Version is 4, then there MUST be 1024 fields specified
	# to fill a 4096-byte sector.

