import binascii
import optparse
def seekAndRead(inFile, hexOffset, hexLength):
	f = open(inFile, 'r')
	f.seek(int(str(hexOffset),16))
	f.close()
	return f.read(int(str(hexLength),16)).encode("hex")

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
			print(binascii.hexlify(content))
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
		# This was a test of seekAndRead, WHALA it worked!
		hexOffset = 2
		hexLength = 4
		print ("Seeking to hexOffset "+str(hexOffset)+"(bytes) , and then reading for hexLength "+str(hexLength)+"(bytes) gives us: "+seekAndRead(inFile, 2, 4))
	except Exception, e:
		print("Error: " + str(e))
			
		
if __name__ == '__main__':
	main()
