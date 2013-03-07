import binascii
import optparse
def header(inFile):
	sig=seekAndRead(inFile,0x0000,8) 		# Header signature
	clsid=seekAndRead(inFile,0x0008,10)		# Header CLSID
	minVersion=seekAndRead(inFile,0x0018,2)		# Minor version
	majVersion=seekAndRead(inFile,0x001A,2) 	# Major version
	byteOrder=seekAndRead(inFile,0x001C,2) 		# Byte order (little/big endian)
	sectSize=seekAndRead(inFile,0x001E,2) 		# Sector Size
	mStreamSectSize=seekAndRead(inFile,0x0020,2) 	# Mini stream sector size
	res=seekAndRead(inFile,0x0022,6) 		# Reserved
	nDirSect=seekAndRead(inFile,0x0028,4) 		# Number of directory sectors
	nFATSect=seekAndRead(inFile,0x002c,4)		# Number of FAT sectors
	dirStartSectLoc=seekAndRead(inFile,0x0030,4) 	# Directory start sector location
	tSig=seekAndRead(inFile,0x0034,4) 		# Transaction signature
	mStreamSizeCutoff=seekAndRead(inFile,0x0038,4) 	# Mini stream size cutoff
	mFATStartSectLoc=seekAndRead(inFile,0x003C,4) 	# Mini FAT start sector location
	nMFATSect=seekAndRead(inFile,0x0040,4) 		# Number of mini FAT sectors
	DIFATStartSectLoc=seekAndRead(inFile,0x0044,4) 	# DIFAT start sector location
	nDIFATSect=seekAndRead(inFile,0x0048,4) 	# Number of DIFAT sectors
	DIFAT=109*[None]				# DIFAT list
	###POPULATE DIFAT[]###
	c = 0	
	for i in range(0, len(DIFAT)):
		offset = hex(int(DIFATStartSectLoc,16)+c)	
		DIFAT[i]=seekAndRead(inFile,offset,20)
		c += 32
	print("Signature\t\t"+sig+"\nCLSID\t\t"+clsid+"\nMinor Version\t\t"+minVersion+\
		"\nMajor Version\t\t"+majVersion+"\nByte Order\t\t"+byteOrder+\
		"\nSector Size\t\t"+sectSize+"\nMini Stream Sector Size\t\t"+mStreamSectSize+\
		"\nReserved\t\t"+res+"\nNumber of Directory sectors\t\t"+nDirSect+\
		"\nNumber of FAT sectors\t\t"+nFATSect+\
		"\nDirectory start sector location\t\t"+dirStartSectLoc+\
		"\nTransaction signature\t\t"+tSig+\
		"\nMini stream size cutoff\t\t"+mStreamSizeCutoff+\
		"\nMini FAT start sector location\t\t"+mFATStartSectLoc+\
		"\nNumber of mini FAT sectors\t\t"+nMFATSect+\
		"\nDIFAT Start Sector Loccation\t\t"+DIFATStartSectLoc+\
		"\nNumber of DIFAT sectors\t\t"+nDIFATSect)	

def seekAndRead(inFile, hexOffset, hexLength):
	f = open(inFile, 'r')
	f.seek(int(str(hexOffset),16))
	out = f.read(int(str(hexLength),16)).encode("hex")
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
			print("WOOT")
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
	
	try: 
		header(inFile)	
	except Exception, e:
		print("Error: " + str(e))
if __name__ == '__main__':
	main()
