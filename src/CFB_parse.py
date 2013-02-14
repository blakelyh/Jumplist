import binascii


filename = 'test.txt'

with open(filename, 'rb') as f:
    content = f.read()
print(binascii.hexlify(content))

