import binascii
import optparse
def header(inFile):
	sig=seekAndRead(inFile,0x0000,0x08) 		# Header signature
	clsid=seekAndRead(inFile,0x0008,0x10)		# Header CLSID
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
	DIFAT=109*[None]				# DIFAT list
	###POPULATE DIFAT
	try:
		print("DIFAT PARSING\n\t\t0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F\n")
		c = 0	
		for i in range(0, len(DIFAT)):
			offset = int(DIFATStartSectLoc,16)+c
			DIFAT[i]=seekAndRead(inFile,offset,32)
			print (str(hex(offset))+"\t"+str(DIFAT[i]))
			c += 32
	except Exception, e:
		print("ERROR PARSING DIFAT "+str(e)+"\n")
	print("\n\nOFFSET\t\t\t\t\t0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F\n\n")
	print("Signature\t\t\t\t"+sig+\
		"\nCLSID\t\t\t\t\t"+clsid+\
		"\nMinor Version\t\t\t\t"+minVersion+\
		"\nMajor Version\t\t\t\t"+majVersion+\
		"\nByte Order\t\t\t\t"+byteOrder+\
		"\nSector Size\t\t\t\t"+sectSize+\
		"\nMini Stream Sector Size\t\t\t"+mStreamSectSize+\
		"\nReserved\t\t\t\t"+res+\
		"\nNumber of Directory sectors\t\t"+nDirSect+\
		"\nNumber of FAT sectors\t\t\t"+nFATSect+\
		"\nDirectory start sector location\t\t"+dirStartSectLoc+\
		"\nTransaction signature\t\t\t"+tSig+\
		"\nMini stream size cutoff\t\t\t"+mStreamSizeCutoff+\
		"\nMini FAT start sector location\t\t"+mFATStartSectLoc+\
		"\nNumber of mini FAT sectors\t\t"+nMFATSect+\
		"\nDIFAT Start Sector Loccation\t\t"+DIFATStartSectLoc+\
		"\nNumber of DIFAT sectors\t\t\t"+nDIFATSect)	

def seekAndRead(inFile, bOffset, bLength):
	f = open(inFile, 'r')
	f.seek(bOffset)
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
	
	try: 
		header(inFile)	
	except Exception, e:
		print("Error: " + str(e))
if __name__ == '__main__':
	main()
