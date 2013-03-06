import binascii
def main():
	filename = 'test.txt'
	try:
		with open(filename, 'rb') as f:
			content = file.read()
	except Exception, e:
		print ("Error: " + e)
	hex = str(binascii.hexlify(content))
	print(hex)
if '__name__' == '__main__':
	main()
