import binascii


filename = 'test.txt'

try:
	with open(filename, 'rb') as f:
    	content = f.read()
	break
except Exception, e:
	print ("Error: " + e)

print(binascii.hexlify(content))

