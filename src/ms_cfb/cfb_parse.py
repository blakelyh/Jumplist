import struct
import binascii
import optparse

def header(inFile):
	sig=seekAndRead(inFile, 0x0000,0x08) 		# Header signature
	clsid=seekAndRead(inFile, 0x0008,0x10)		# Header CLSID
	minVersion=seekAndRead(inFile,0x0018,0x02)	# Minor version
	majVersion=seekAndRead(inFile,0x001A,0x02) 	# Major version
	byteOrder=seekAndRead(inFile,0x001C,0x02) 	# Byte order (little/big endian)
	sectSize=seekAndRead(inFile,0x001E,0x02) 	# Sector Size
	mStreamSectSize=seekAndRead(inFile,0x0020,0x02) # Mini stream sector size
	res=seekAndRead(inFile,0x0022,0x06) 		# Reserved
	nDirSect=seekAndRead(inFile,0x0028,0x04) 	# Number of directory sectors
	nFATSect=seekAndRead(inFile,0x002c,0x04)	# Number of FAT sectors
	dirStartSectLoc=seekAndRead(inFile,0x0030,0x04) # Directory start sector location
	tSig=seekAndRead(inFile,0x0034,0x04) 		# Transaction signature
	mStreamSizeCutoff=seekAndRead(inFile,0x0038,0x04) # Mini stream size cutoff
	mFATStartSectLoc=seekAndRead(inFile,0x003C,0x04) # Mini FAT start sector location
	nMFATSect=seekAndRead(inFile,0x0040,0x04) 	# Number of mini FAT sectors
	DIFATStartSectLoc=seekAndRead(inFile,0x0044,0x04) # DIFAT start sector location
	nDIFATSect=seekAndRead(inFile,0x0048,0x04) 	# Number of DIFAT sectors
	DIFAT=109*[None]
	###POPULATE DIFAT
	try:
		#Testing purposes print("DIFAT PARSING\n\t\t0 1 2 3 4 5 6 7 8 9"+\
		# " A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F\n")
		c = 0	
		for i in range(0, len(DIFAT)):
			offset = int(DIFATStartSectLoc,16)+c
			DIFAT[i]=seekAndRead(inFile,offset,32)
			#Testing Purposes print (str(hex(offset))+"\t"+str(DIFAT[i]))
			c += 32
	except Exception, e:
		print("ERROR PARSING DIFAT "+str(e)+"\n")
	
	# TESTING PURPOSES
	print("IN HEADER FUNCTION")
	#print("\n\nOFFSET\t\t\t\t\t0 1 2 3 4 5 6 7 8 9 "+\
	#"A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F\n\n"+\
	#	"\nSignature\t\t\t\t"+sig+\
	#	"\nCLSID\t\t\t\t\t"+clsid+\
	#	"\nMinor Version\t\t\t\t"+minVersion+\
	#	"\nMajor Version\t\t\t\t"+majVersion+\
	#	"\nByte Order\t\t\t\t"+byteOrder+\
	#	"\nSector Size\t\t\t\t"+sectSize+\
	#	"\nMini Stream Sector Size\t\t\t"+mStreamSectSize+\
	#	"\nReserved\t\t\t\t"+res+\
	#	"\nNumber of Directory sectors\t\t"+nDirSect+\
	#	"\nNumber of FAT sectors\t\t\t"+nFATSect+\
	#	"\nDirectory start sector location\t\t"+dirStartSectLoc+\
	#	"\nTransaction signature\t\t\t"+tSig+\
	#	"\nMini stream size cutoff\t\t\t"+mStreamSizeCutoff+\
	#	"\nMini FAT start sector location\t\t"+mFATStartSectLoc+\
	#	"\nNumber of mini FAT sectors\t\t"+nMFATSect+\
	#	"\nDIFAT Start Sector Loccation\t\t"+DIFATStartSectLoc+\
	#	"\nNumber of DIFAT sectors\t\t\t"+nDIFATSect)	
	#	
	if (str(byteOrder) == "feff"):
		print("\tByte Order = Little Endian, must flip bytes")

def fat(inFile, version, nFATSect, sectSize):
	print("IN FAT SECTOR FUNCTION")
	if (nFATSect>0):
		start=sectSize
		stepL=0x04
		end=int(start)+(int(nFATSect)*int(sectSize))
		nxtSect=int(nFATSect)*(int(sectSize)/int(stepL))*[None]
		c = 0
		for i in range (start,end,stepL):
			nxtSect[c]=seekAndRead(inFile,i,stepL)
			#print("nxtSect["+str(c)+"]:\t"+str(nxtSect[c])+"\n")
			c += 1
	# FOR TESTING
	#print("\nFile Name\t\t"+inFile+\
	#"\nVersion\t\t\t"+str(int(version))+\
	#"\nNumber of FAT Sectors\t"+str(int(nFATSect))+\
	#"\nStart\t\t\t"+str(hex(start))+\
	#"\nStep size\t\t"+str(hex(stepL))+\
	#"\nStep x nSect\t\t"+str(hex(int(stepL)*int(nFATSect)))+\
	#"\nEnd\t\t\t"+str(hex(end)))


def dir(inFile, version, dirStartSectLoc, sectSize, nDirSect):
	print("IN DIRECTORY SECTOR FUNCTION")
	sectSize = 2**(int(sectSize))
	start = int(dirStartSectLoc)*sectSize+sectSize
	if(nDirSect>0):
		dirEntryName=seekAndRead(inFile,start,64) 
		start +=64; #print("DirEntryN\t"+str(dirEntryName)) 
		dirEntryNameLen=seekAndRead(inFile,start,2)
		start +=2; #print("dirEntryNL\t"+str(dirEntryNameLen))
		objType=seekAndRead(inFile,start,1)
		start +=1; #print("objType\t\t"+str(objType))
		cFlag=seekAndRead(inFile,start,1)
		start +=1; #print("color flag\t"+str(cFlag))
		lSID=seekAndRead(inFile,start,4)
		start +=4; #print("lSiblingID\t"+str(lSID))
		rSID=seekAndRead(inFile,start,4)
		start +=4; #print("rSiblingID\t"+str(rSID))
		childID=seekAndRead(inFile,start,4)
		start +=4; #print("child ID\t"+str(childID))
		clsid=seekAndRead(inFile,start,16)
		start +=16; #print("clsid\t\t"+str(clsid))
		sFlags=seekAndRead(inFile,start,4)
		start +=4; #print("sFlags\t\t"+str(sFlags))
		cTime=seekAndRead(inFile,start,8)
		start +=8; #print("cTime\t\t"+str(cTime))
		modTime=seekAndRead(inFile,start,8)
		start +=8; #print("modTime\t\t"+str(modTime))
		sSectLoc=seekAndRead(inFile,start,4)
		#print("sSectLoc\t"+str(sSectLoc))
	# FOR TESTING
	print("\tmust iterate through all dir sectors")

def mFAT(inFile, sectSize, mSSCutoff, mFATStartSectLoc, nMFATSect):
	print("IN MINI FAT SECTOR FUNCTION")
	if(nMFATSect>0):
		sSize=2**(int(sectSize))
		start=int(mFATStartSectLoc)*sSize+sSize
		end=start+sSize
		stepL=0x04	
		nxtSect=int(sSize)/int(stepL)*[None]
		c=0
		for i in range(start,end,stepL):
			nxtSect[c]=seekAndRead(inFile,i,stepL)
			#print("Offset "+str(hex(i))+"\tVal "+str(nxtSect[c]))
			c+=1
		print("\tMUST ITERATE FOR EACH MINI FAT SECTOR")

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

def main():
	parser = optparse.OptionParser('usage%prog '+\
		'-i <INPUT FILE> -o <OUTPUT FILE>')
	parser.add_option('-i', dest='iFile', type='string',\
		help='Specify an input file: -i inputFileName')
	parser.add_option('-o', dest='oFile', type='string',\
		help='Specify an output file: -o outputFileName')
	(options, args)=parser.parse_args()
	inFile = options.iFile
	outFile = options.oFile
	if inFile == None:
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
	header(inFile)
	# fat(inFile, version, nFATSect, sectSize)
	fat(inFile, 0x0003, 0x000001, 0x0200)
	# dir(inFile, version, dirstartSectLoc, sectSize, nDirSect)
	dir(inFile, 0x0003, 0x00000001, 0x0009, 0x2800)
	# mFAT(iFile, sectSize, mSSCutoff, mFATStartSectLoc, nMFATSect)
	mFAT(inFile, 0x0009, 0x00001000, 0x00000002, 0x00000001)
if __name__ == '__main__':
	main()
