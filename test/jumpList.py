import glob
import re
import binascii
import optparse
def cfb_header(inFile):
	head=18*[None]
	head[0]=seekAndRead(inFile, 0x0000,0x08) 	# Header signature
	head[1]=seekAndRead(inFile, 0x0008,0x10)	# Header CLSID
	head[2]=seekAndRead(inFile,0x0018,0x02)		# Minor version
	head[3]=seekAndRead(inFile,0x001A,0x02) 	# Major version
	head[4]=seekAndRead(inFile,0x001C,0x02) 	# Byte order (little/big endian)
	head[5]=seekAndRead(inFile,0x001E,0x02) 	# Sector Size
	head[6]=seekAndRead(inFile,0x0020,0x02) 	# Mini stream sector size
	head[7]=seekAndRead(inFile,0x0022,0x06) 	# Reserved
	head[8]=seekAndRead(inFile,0x0028,0x04) 	# Number of directory sectors
	head[9]=seekAndRead(inFile,0x002c,0x04)		# Number of FAT sectors
	head[10]=seekAndRead(inFile,0x0030,0x04)	# Directory start sector location
	head[11]=seekAndRead(inFile,0x0034,0x04)	# Transaction signature
	head[12]=seekAndRead(inFile,0x0038,0x04)	# Mini stream size cutoff
	head[13]=seekAndRead(inFile,0x003C,0x04)	# Mini FAT start sector location
	head[14]=seekAndRead(inFile,0x0040,0x04)	# Number of mini FAT sectors
	head[15]=seekAndRead(inFile,0x0044,0x04)	# DIFAT start sector location
	head[16]=seekAndRead(inFile,0x0048,0x04)	# Number of DIFAT sectors
	DIFAT=109*[None]
	if (int(head[7],16)!=0):				# Verify inFIle is Jump List
		print (str(inFile)+" IS NOT A JUMP LIST!")
		exit(0)					
	if (str(head[4]) == "feff"):				# Determine Byte Order
		for index, object in enumerate(head):
			if (type(object)== str):
				try:
					head[index]=revByteOrd(long(object,16))
				except Exception, e:
					print e
	if(int(head[15],16)<int("0xfffffffa",16)):		# DIFAT REG_SECT check
		c = 0	
		for i in range(0, len(DIFAT)):
			offset = int(head[15],16)+c
			DIFAT[i]=seekAndRead(inFile,offset,32)
			c += 32
	if (str(head[4]) == "0xfffe"):				# DIFAT bSwap if Little Endian
		for i, o in enumerate(DIFAT):
			if (o!="")and(o!=None):
				DIFAT[i]=revByteOrd(long(o,16))
	head[17]=DIFAT						# DIFAT Array
	return head				
	
def cfb_fat(inFile, version, sectSize, nFATSect):
	stepL=0x04                              	# Step length  
	start=sSize=2**(int(str(sectSize),16))		# sSize offset
	end=start+sSize	         			# End of FAT
	f=int(nFATSect,16)*[None]			# FAT sectors Array
	for index in range(0,int(nFATSect,16)):
		nxtSect=sSize/int(stepL)*[None] 	# nxtSect Array
		c = 0 					# index for nxtSect
		if(int(version,16) == 3):		# Version 3, revByteOrd
			for i in range (start,end,stepL):
				nxtSect[c]=revByteOrd(long(seekAndRead(inFile,i,stepL),16))
				c += 1
		else:					# Not version 3
			for i in range (start,end,stepL):
				nxtSect[c]=seekAndRead(inFile,i,stepL)
				c += 1
	f[index]=nxtSect
 	return f

def cfb_dir(inFile, version, sectSize, dirStartSectLoc, nDirSect):
	sSize = 2**(int(sectSize,16))				# size is 2^sectSize
	start = int(dirStartSectLoc,16)*sSize+sSize		# start location 
	# Fill Array[index] with fully populated d[].
	if (int(version,16)==3 and int(nDirSect)!=0):
			print str(inFile)+" is corrupt, or is not a jump list."
			exit(0)
	elif (int(version,16)==3):
		number = 1 					# number is nDirSect
	else:
		number = int(nDirSect,16)
	di=number*[None]
	for index in range(0,number):
		d=12*[None]					# Dir Array
		d[0]=seekAndRead(inFile,start,64);start +=64  	# Dir Entry Name
		d[1]=seekAndRead(inFile,start,2);start +=2	# Dir Entry Name Length
		d[2]=seekAndRead(inFile,start,1);start +=1	# objType
		d[3]=seekAndRead(inFile,start,1);start +=1	# cFlag
		d[4]=seekAndRead(inFile,start,4);start +=4	# lSID
		d[5]=seekAndRead(inFile,start,4);start +=4	# rSID
		d[6]=seekAndRead(inFile,start,4);start +=4	# childID
		d[7]=seekAndRead(inFile,start,16);start +=16	# clsid
		d[8]=seekAndRead(inFile,start,4);start +=4	# sFlags
		d[9]=seekAndRead(inFile,start,8);start +=8	# cTime
		d[10]=seekAndRead(inFile,start,8);start +=8	# modTime
		d[11]=seekAndRead(inFile,start,4)		# sSectLoc
		if (int(version,16)==3):
			for i in range (len(d)):
				d[i]=revByteOrd(long(d[i],16))
		di[index]=d
	return di

def cfb_mFAT(inFile, version, sectSize, mSSCutoff, mFATStartSectLoc, nMFATSect):
	if(nMFATSect>0):
		stepL=0x04	
		start=sSize=2**(int(sectSize,16))
		start+=int(mFATStartSectLoc,16)*sSize 	
		end=start+sSize
		mF=int(nMFATSect,16)*[None]
		for index in range(0,int(nMFATSect,16)):
			nxtSect=sSize/int(stepL)*[None]
			c=0
			if(int(version,16)==3):
				for i in range(start,end,stepL):
					nxtSect[c]=revByteOrd(long(seekAndRead(inFile,i,stepL),16))
					c+=1
			else:
				for i in range(start,end,stepL):
					nxtSect[c]=seekAndRead(inFile,i,stepL)
					c+=1
			mF[index]=nxtSect
		return mF

def shellLink_header(inFile):
	head=14*[None]
	head[0]=seekAndRead(inFile, 0x0000,0x04) 	# HeaderSize 
	head[1]=seekAndRead(inFile, 0x0004,0x10)	# LinkCLSID
	head[2]=seekAndRead(inFile,0x0014,0x04)		# LinkFlags
	head[3]=seekAndRead(inFile,0x0018,0x04) 	# FileAttributes
	head[4]=seekAndRead(inFile,0x001C,0x08) 	# CreationTime
	head[5]=seekAndRead(inFile,0x0024,0x08) 	# AccessTime
	head[6]=seekAndRead(inFile,0x002c,0x08) 	# WriteTime
	head[7]=seekAndRead(inFile,0x0034,0x04) 	# FileSize
	head[8]=seekAndRead(inFile,0x0038,0x04) 	# IconIndex
	head[9]=seekAndRead(inFile,0x003c,0x04)		# ShowCommand
	head[10]=seekAndRead(inFile,0x0040,0x02)	# HotKey
	head[11]=seekAndRead(inFile,0x0042,0x02)	# Reserved1
	head[12]=seekAndRead(inFile,0x0044,0x04)	# Reserved2
	head[13]=seekAndRead(inFile,0x0048,0x04)	# Reserved3
	# Header check
	if head[0] != 0x0000004C:
		print "INVALID FILE... Shell Link header: "+str(head[0])+\
		" must be: 0x0000004C"
	# LinkCLSID check
	#if str(head[1]) != "00021401-0000-0000-C000-000000000046":
	#	print "INVALID FILE... Shell Link LinkCLSID"+str(head[1]+\
	#	" must be: 00021401-0000-0000-C000-000000000046"
	# Filesize check: MUST MAKE THE COMPARISON BETWEEN UNSIGNED VALUES!
	#if head[7] > 0xFFFFFFFF:
	#	print "Shell Link File size: "+str(head[7])+"represents the least"+\
	#	"significant 32 bits of the link target file size."
	# ShowCommand is a 32-bit unsigned int that specifies expected window size
	# of an application launched by the link. This value should be one of the following:
	SW_SHOWNORMAL = 0x00000001
	SW_SHOWMAXIMIZED = 0x00000003
	SW_SHOWMINNOACTIVE = 0x00000007
	# ALL OTHER VALUES MUST BE TREATED AS SHOW NORMAL
	if head[9] == SW_SHOWNORMAL:
		print "Shell Link application opens in normal fashion: "+\
		str(SW_SHOWNORMAL)
	elif head[9] == SW_SHOWMAXIMIZED:
		print "Shell Link application is given keyboard focus upon opening,"+\
		"but the window is not shown: "+str(SW_SHOWMAXIMIZED)
	elif head[9] == SW_SHOWMINNOACTIVE:
		print "Shell Link application is open, but window is not shown."+\
		"It is not given the keybaord focus: "+str(SW_SHOWMINNOACTIVE)
	else:
		print "ShowCommand option: "+str(head[9])+" is inappropriate"+\
		", chaning the value to SW_SHOWNORMAL (0x00000001)."
		head[9] = SW_SHOWNORMAL
	print "In shell link header, must write link flags section."
	print "In shell link header, must write file attributes flags section."
	print "In shell link header, must write hotkey flags section."
	return head				

def shellLink_linkTargetIDLIST():
	print "Fix link target ID list"
	IDListSize = 0 # 2 bytes, size in bytes of the IDList Field
	IDList ='' # A stored IDList structure which contains the item ID list.
	# IDList structure conforms to the following ABNF [RFC5234]
	numIDList = 0 # CHANGE THIS NUMBER !!!!!!!
	ItemIDList = numIDList*[None] # an array of zero or more ItemID structures
	TerminalID = 0 # A 16-bit, unsigned int that indicates the end of the item IDs. # MUST BE 0
	ItemID = 2*[None] # element in IDList. contains ItemIDSize and Data
	ItemIDSize = 0	# Stored in ItemID, 16-bit unsigned int, specifies size in bytes of id struct
	data = '' # Stored in ItemID, shell data source- defined data specifies an item
	return ItemIDList

def shellLink_linkInfo():
	print "fix link info"
	ret = 15*[None] 	# Return Variable
	# LINK INFO STRUCTURE
	LIS = 0 		# LinkInfoSize 
	LIHS = 0		# LinkInfoHeaderSize
	LIF = 0 		# LinkInfoFlags
	VolIDOff = 0		# VolumeIDOffset
	LBPOff = 0		# LocalBasePathOffset
	CNetRelLOff = 0		# CommonNetworkRelativeLinkOffset
	CPSufOff = 0		# CommonPathSuffixOffset
	LBPOffU = 0		# LocalBasePathOffsetUnicode 
	CPSuffOffU = 0		# CommonPathSuffixOffsetUnicode
	VolumeID = 6*[None]	# VolumeID
	LBPath = 0 		# LocalBasePath
	CNetRelLink = 11*[None]	# CommonNetworkRelativeLink
	CPSuff = 0		# CommonPathSuffix
	LBPU = 0 		# LocalBasePathUnicode
	CPSuffU = 0		# CommonPathSuffixUnicode
	
	# VOLUMEID STRUCTURE
	VolIDS = 0 	# VolumeIDSize
	DType = 0 	# DriveType can be: 0x1,0x2,0x3,0x4,0x5 or 0x6 
	DSerNum = 0 	# DriveSerialNumber
	VolLOff = 0 	# VolumeLabelOffset
	VolLOffUni = 0 	# VolumeLabelOffsetUnicode 
	vData = 0 	# Data
	VolumeID = [VolIDS,DType,DSerNum,VolLOff,VolLOffUni,vData]	

	# CommonNetworkRelativeLink STRUCTURE
	CNRelLinkS = 0 		# CommonNetworkRelativeLinkSize
	CNetRelLinkF = 0 	# CommonNetworkRelativeLinkFlags
	NetNOff = 0 		# NetNameOffset
	DNOff = 0		# DeviceNameOffset
	NetPT = 0		# NetworkProviderType
	NetNOffU = 0 		# NetNameOffsetUnicode 
	DNOffU = 0		# DeviceNameOffsetUnicode
	NetN = 0 		# NetName
	DN = 0 			# DeviceName
	NetNU = 0 		# NetNameUnicode
	DNU = 0			# DeviceNameUnicode
	NETRelLink=[CNRelLinkS,CNetRelLinkF,NetNOff,DNOff,NetPT,NetNOffU,DNOffU,NetN,DN,NetNU,DNU]

	ret=[LIS,LIHS,LIF,VolIDOff,CPSufOff,LBPOffU,CPSuffOffU,VolumeID,LBPath,CNetRelLink,CPSuff,LBPU,CPSuffU]	
	return ret

def shellLink_stringData():
	print "fix string data"
	# STRING_DATA = [NAMESTRING] [RELATIVEPATH] [WORKINGDIR] [COMMANDLINEARGUMENTS] [ICONLOCATION]
	NAME_STRING = 1*[None] 	# Must be present if HasName flag is set
	RELATIVE_PATH = 1*[None] 	# Must be present if HasRelativePath flag is set
	WORKING_DIR = 1*[None] # Must be present if HasWorkingDir flag is set	
	COMMAND_LINE_ARGUMENTS = 1*[None] 	# Must be present if HasArguments flag is set
	ICON_LOCATION = 1*[None] 	# Must be present if HasIconLocation flag is set
	CountCharacters = 0
	String = '' # MUST NOT BE NULL-TERMINATED!
	ret = [CountCharacters, String]
	return ret

def shellLink_extraData():
	print "fix extra data"
	EXTRA_DATA = 0
	EXTRA_DATA_BLOCK = 0
	CONSOLE_PROPS = 0
	CONSOLE_FE_PROPS = 0
	DARWIN_PROPS = 0
	ENVIRONMENT_PROPS = 0
	ICON_ENVIRONMENT_PROPS = 0
	KNOWN_FOLDER_PROPS = 0
	PROPERTY_STORE_PROPS = 0
	SHIM_PROPS = 0
	SPECIAL_FOLDER_PROPS = 0
	TRACKER_PROPS = 0
	VISTA_AND_ABOVE_IDLIST_PROPS = 0
	TERMINAL_BLOCK = 0
	ret = 14*[None]
	return ret

def seekAndRead(inFile, bOffset, bLength):
	try:
		f = open(inFile, 'r')				# Open file
	except Exception, e:
		print("Error opening <"+inFile+">: "+str(e))
	try:
		f.seek(bOffset)					# Seek to offset
	except Exception, e:
		print("Error seeking to "+str(bOffset)+" "+str(e))
	out = f.read(bLength).encode("hex")			# Read for length
	f.close()						# Close file
	return out 

def revByteOrd(data):
	s = "Error: Only 'unsigned' data of type 'int' or 'long' is allowed"
	if not ((type(data) == int)or(type(data) == long)):
		s1 = "Error: Invalid data type: %s" % type(data)
		print(''.join([s,'\n',s1]))
    		return data
	if(data < 0):
		s2 = "Error: Data is signed. Value is less than 0"
		print(''.join([s,'\n',s2]))
		return data
	seq = ["0x"]
	if data==0:
		return int(data)
	else:
		while(data > 0):
			d = data & 0xFF     # extract the least significant(LS) byte
			seq.append('%02x'%d)# convert string, append to sequence
			data >>= 8          # push next higher byte to LS position
			revD = int(''.join(seq),16)
	return hex(revD)

def progMatch(inFile):
	path1 = "./path1/" # automatic
	path2 = "./path2/" # custom
	try:
		List = open(str(inFile)).readlines()
	except Exception, e:
		print "error reading program file"
	retArray = len(List)*[None]
	count = 0
	try:
		for p in List:
			if p[0] != ':' and p[0] != '\n' and p != None:
				s = p.split()
				pSt = ""
				for num in range(1,len(s)):
					pSt = pSt+s[num]+" "
				#print "UUID for "+pSt+"is: "+str(s[0])
				try:
					matchedFile = glob.glob(path1+str(s[0])+"*")
				except Exception, e:
					print "file not found"
				if str(matchedFile[0]) != 'file not found':
					retArray[count]=matchedFile[0]
					#print retArray
				count = count + 1
	except Exception, e:
		print "error parsing program file: "+str(e)
	return retArray

def parseCFB(inFile):
	h = cfb_header(inFile)
	f = cfb_fat(inFile, h[3], h[5], h[9])
	d = cfb_dir(inFile, h[3], h[5], h[10], h[8])
	m = cfb_mFAT(inFile, h[3], h[5], h[12], h[13], h[14])
	#print "header \n"+str(h)
	#print "FAT \n"+str(f)
	#print "directory \n"+str(d)
	#print "mFAT \n"+str(m)
	ret=[h,f,d,m]
	return ret

def parseSHLLINK(inFile):
	h = shellLink_header(inFile)
	idL = shellLink_linkTargetIDLIST()
	lI = shellLink_linkInfo()
	sD = shellLink_stringData()
	eD = shellLink_extraData()
	ret = [h,idL,lI,sD,eD]
	return ret

def main():
	parser = optparse.OptionParser('\n\t%prog '+\
		'[-i <INPUT FILE>] [-p <PROGRAMS FILE>] -o <OUTPUT FILE>'+\
		'\n\n\t\t* An OUPUT FILE is required.'+\
		'\n\n\t\t* If no INPUT/PROGRAMS FILE exists but OUTPUT '+\
		'FILE does exist:'+\
		'\n\t\t\tAll jump list files will be selected.'+\
		'\n')
	parser.add_option('-i', dest='iFile', type='string',\
		help='Specify an input file: -i inputFileName')
	parser.add_option('-o', dest='oFile', type='string',\
		help='Specify an output file: -o outputFileName')
	parser.add_option('-p', dest='pF', type='string',\
		help='Specify an input file: -p programsConfigFile')
	(options, args)=parser.parse_args()
	pFile = options.pF
	inFile = options.iFile
	outFile = options.oFile
	content = None
	################ must have OUTPUT FILE ########## #########
	if outFile == None:
		print parser.usage	
		exit(0)
	################# if pFile exists Match Progs ############
	if pFile != None:
		progArray = progMatch(pFile)
		try: 
			for files in progArray:
				parseCFB(str(files))
		except Exception, e:
			print ("Error parsing file in progArray: "+str(e))
	################## if inFile exists parse it #############
	if inFile != None:	
		try:
			parseCFB(inFile)			
		except Exception, e:
			print ("Error: " + str(e))
	############## if ! inFile/pFile, parse all jumplists ####
	elif inFile == None and pFile == None:
		# Search for all jump list files
		print"All Jump List Files shall be parsed."
	################### PARSE SHELLINK #######################
	parseSHLLINK(inFile)	
	############## PRINT OUTPUT TO OUTPUT FILE ###############	
	print "WRITE TO THE OUTPUT FILE: "+outFile
	
if __name__ == '__main__':
	main()
