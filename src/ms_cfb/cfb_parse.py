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
	if (int(head[7],16)!=0):			# Verify inFIle is Jump List
		print (str(inFile)+" IS NOT A JUMP LIST!")
		exit(0)					
	if (str(head[4]) == "feff"):			# Determine Byte Order
		for index, object in enumerate(head):
			if (type(object)== str):
				try:
					head[index]=hex(revByteOrd(long(object,16)))
				except Exception, e:
					print e
	if(int(head[15],16)<int("0xfffffffa",16)):	# DIFAT REG_SECT check
		c = 0	
		for i in range(0, len(DIFAT)):
			offset = int(head[15],16)+c
			DIFAT[i]=seekAndRead(inFile,offset,32)
			c += 32
	if (str(head[4]) == "0xfffe"):			# DIFAT bSwap if Little Endian
		for i, o in enumerate(DIFAT):
			if (o!="")and(o!=None):
				DIFAT[i]=hex(revByteOrd(long(o,16)))
	head[17]=DIFAT					# DIFAT Array
	return head					

def fat(inFile, version, nFATSect, sectSize):
	if (nFATSect>0):						# Check # of FAT > 0
		start=sectSize						# Start offset
		stepL=0x04						# Step length
		end=int(start)+(int(nFATSect)*int(sectSize))		# End of FAT
		nxtSect=int(nFATSect)*(int(sectSize)/int(stepL))*[None]	# nxtSect Array
		c = 0
		for i in range (start,end,stepL):
			nxtSect[c]=seekAndRead(inFile,i,stepL)
			c += 1
		return nxtSect		

def dir(inFile, version, dirStartSectLoc, sectSize, nDirSect):
	sectSize = 2**(int(sectSize))				# size is 2^sectSize
	start = int(dirStartSectLoc)*sectSize+sectSize		# start location 
	


	# MUST LOOP THIS SECTION
	# for each sector:
	# Fill Array[index] with fully populated d[].
	d=12*[None]						# return d Array
	if(nDirSect>0):
		d[0]=seekAndRead(inFile,start,64)	# Dir Entry Name
		start +=64;  					
		d[1]=seekAndRead(inFile,start,2)	# Dir Entry Name Length
		start +=2; 
		d[2]=seekAndRead(inFile,start,1)	# objType
		start +=1; 
		d[3]=seekAndRead(inFile,start,1)	# cFlag
		start +=1; 
		d[4]=seekAndRead(inFile,start,4)	# lSID
		start +=4; 
		d[5]=seekAndRead(inFile,start,4)	# rSID
		start +=4; 
		d[6]=seekAndRead(inFile,start,4)	# childID
		start +=4; 
		d[7]=seekAndRead(inFile,start,16)	# clsid
		start +=16; 
		d[8]=seekAndRead(inFile,start,4)	# sFlags
		start +=4; 
		d[9]=seekAndRead(inFile,start,8)	# cTime
		start +=8; 
		d[10]=seekAndRead(inFile,start,8)	# modTime
		start +=8; 
		d[11]=seekAndRead(inFile,start,4)	# sSectLoc
	return d

def mFAT(inFile, sectSize, mSSCutoff, mFATStartSectLoc, nMFATSect):
	# 
	if(nMFATSect>0):
		sSize=2**(int(sectSize))
		start=int(mFATStartSectLoc)*sSize+sSize
		end=start+sSize
		stepL=0x04	
		nxtSect=int(sSize)/int(stepL)*[None]
		c=0
		for i in range(start,end,stepL):
			nxtSect[c]=seekAndRead(inFile,i,stepL)
			c+=1
		return nxtSect

def seekAndRead(inFile, bOffset, bLength):
	try:
		f = open(inFile, 'r')
	except Exception, e:
		print("Error opening <"+inFile+">: "+str(e))
	try:
		f.seek(bOffset)
	except Exception, e:
		print("Error seeking to "+str(bOffset)+" "+str(e))
	out = f.read(bLength).encode("hex")
	f.close()
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
		return data
	else:
		while(data > 0):
			d = data & 0xFF     # extract the least significant(LS) byte
			seq.append('%02x'%d)# convert string, append to sequence
			data >>= 8          # push next higher byte to LS position
			revD = int(''.join(seq),16)
	return revD

def main():
	parser = optparse.OptionParser('\n\n\t\tusage%prog '+\
		'-i <INPUT FILE> -o <OUTPUT FILE>'+\
		#'\n\n\t\t* If no input file is specified:'+\
		#'\n\t\t\t1) All jump list files will be selected.'+\
		#'\n\t\t\t2) An output file must be specified.')
		'\n\n')
	parser.add_option('-i', dest='iFile', type='string',\
		help='Specify an input file: -i inputFileName')
	parser.add_option('-o', dest='oFile', type='string',\
		help='Specify an output file: -o outputFileName')
	(options, args)=parser.parse_args()
	inFile = options.iFile
	outFile = options.oFile
	if inFile == None and outFile == None:
		print parser.usage	
		exit(0)
	
	try:			
		with open(inFile, 'rb') as f:
			content = f.read()
	except Exception, e:
		print ("Error: " + str(e))
	if outFile == None:
		try:
			print("HEX DUMP SQUELCHED FOR TESTING")
			#print(inFile+" Hex Dump:\n"+binascii.hexlify(content)+"\n")
		except Exception, e:
			print("Error: " + str(e))
	elif outFile != None:
		try:
			hexDumpFile = open(outFile, 'w+')
			hexDumpFile.write(binascii.hexlify(content))
			hexDumpFile.close()
		except Exception, e:
			print("Error: " + str(e))
	# header(inFile)
	h = header(inFile)
	# fat(inFile, version, nFATSect, sectSize)
	f = fat(inFile, 0x0003, 0x000001, 0x0200)
	# dir(inFile, version, dirstartSectLoc, sectSize, nDirSect)
	d = dir(inFile, 0x0003, 0x00000001, 0x0009, 0x2800)
	# mFAT(iFile, sectSize, mSSCutoff, mFATStartSectLoc, nMFATSect)
	m = mFAT(inFile, 0x0009, 0x00001000, 0x00000002, 0x00000001)
if __name__ == '__main__':
	main()
