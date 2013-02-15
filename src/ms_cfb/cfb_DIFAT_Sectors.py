from vutils import *
def cfb_DIFAT_Sectors():

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


