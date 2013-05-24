import binascii
import optparse

def header(inFile):
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

def fat(inFile, version, sectSize, nFATSect):
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

def dir(inFile, version, sectSize, dirStartSectLoc, nDirSect):
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
		d=12*[None]										# Dir Array
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

def mFAT(inFile, version, sectSize, mSSCutoff, mFATStartSectLoc, nMFATSect):
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
	# for each line in file switch statement to match the programs to the list.
	# create array of file names that match the associated program.	
	# parse for each matched file.
	print "in progMatch"
	try:
		with open(inFile, 'rb') as f:
			content = f.read()				
	except Exception, e:
		print("Error: " + str(e))		
	print "after trying to read pFile"
	# for each line in content, if string does not match ^: fill progs.
	# progs = len(file)*[None]
	# fill progs with the appropriate file names corresponding to the program name

def parseCFB(inFile):
	# for each program/input file.
	h = header(inFile)
	f = fat(inFile, h[3], h[5], h[9])
	d = dir(inFile, h[3], h[5], h[10], h[8])
	m = mFAT(inFile, h[3], h[5], h[12], h[13], h[14])
	print "header \n"+str(h)
	print "FAT \n"+str(f)
	print "directory \n"+str(d)
	print "mFAT \n"+str(m)

def parseSHLLINK(data):
	print "write the code to parse shell-link"

def main():
	parser = optparse.OptionParser('\n\tusage%prog '+\
		'[-i <INPUT FILE>] [-p <PROGRAMS FILE>] [-o <OUTPUT FILE>]'+\
		#'\n\n\t\t* If no input file is specified:'+\
		#'\n\t\t\t1) All jump list files will be selected.'+\
		#'\n\t\t\t2) An output file must be specified.')
		'\n')
	parser.add_option('-i', dest='iFile', type='string',\
		help='Specify an input file: -i inputFileName')
	parser.add_option('-o', dest='oFile', type='string',\
		help='Specify an output file: -o outputFileName')
	parser.add_option('-p', dest='pF', type='string',\
		help='Specify an input file: -p programsConfigFile')
	(options, args)=parser.parse_args()


	# Input file to read can be specific file: 1b4dd67f29cb1962.jumplist
	# Input file can be a string with program names, or a file with program names
	pFile = options.pF
	inFile = options.iFile
	outFile = options.oFile

	if pFile != None:
		#	progMatch(pFiled)
		try:
			with open(pFile, 'rb'):
				progMatch(pFile)
		except Exception, e:
			print "prog file does not exist"
		print "write pFile matching"
	elif inFile == None and outFile == None:
		print parser.usage	
		exit(0)
	elif inFile == None:
		# Search for all jump list files
		print"All Jump List Files shall be parsed."
	

	################# GET CONTENT FROM inFile #################
	try:			
		with open(inFile, 'rb') as f:
			content = f.read()
	except Exception, e:
		print ("Error: " + str(e))
	

	############## PRINT OUTPUT TO OUTPUT FILE ###############	
	if outFile == None:
		try:
			parseCFB(inFile)
			#parseSHLLINK(inFile)
			print "No Output File"
		except Exception, e:
			print("Error: " + str(e))
	######## Output file should probably be a csv. ##########
	elif outFile != None:
		try:
			hexDumpFile = open(outFile, 'w+')
			hexDumpFile.write(binascii.hexlify(content))
			hexDumpFile.close()
		except Exception, e:
			print("Error: " + str(e))
if __name__ == '__main__':
	main()
