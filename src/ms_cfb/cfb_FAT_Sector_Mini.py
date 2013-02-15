from vutils import *

def cfb_FAT_Sector_Mini():
	# 2.4 Compound File Mini FAT Sectors #
	Next_Sector_in_Chain_Mini = ''		# LENGTH: variable
	# This field specifies the next sector number in a chain of sectors.
	# If Header Major Version is 3, then there MUST be 128 fields specified 
	# to fill a 512-byte sector.
	# If Header Major Version is 4, then there MUST be 1024 fields specified
	# to fill a 4096-byte sector.
