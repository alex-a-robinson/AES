import hashlib
from copy import copy
from random import randint

sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]

sboxInv = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]

rcon = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
        ]

def rotate(word, n):
	'''Rotates a word n bytes'''
	return word[n:]+word[0:n]

def shiftRows(state):
	'''Shift bytes to the left for each row'''
	for i in range(4):
		state[i*4:i*4+4] = rotate(state[i*4:i*4+4], i)

def shiftRowsInv(state):
	'''Inverse of shiftRows - Shifts bytes to the right for each row'''
	for i in range(4):
		state[i*4:i*4+4] = rotate(state[i*4:i*4+4], -i)

def keyScheduleCore(word, i):
	'''Perform the 4 basic actions on a word'''
	word = rotate(word, 1) # rotate word 1 byte left
	newWord = []
	for byte in word: # sbox substitution for all bytes in word
		newWord.append(sbox[byte])
	newWord[0] = newWord[0] ^ rcon[i] # Xor rcon[i] with first byte of word
	return newWord

def expandKey(cipherKey):
	'''Expands a 256 cipher key into a 240 byte key which each round key is derived from'''
	cipherKeySize = len(cipherKey)
	assert cipherKeySize == 32 # Raise error if cipherKey is not 32 bytes
	expandedKey = [] # will contain expanded key
	currentSize = 0
	rconIter = 1
	t = [0, 0, 0, 0] # temporary list to store 4 bytes
	
	# Copy the cipher key to the first 32 bytes of the expaned key
	for i in range(cipherKeySize):
		expandedKey.append(cipherKey[i])
	currentSize += cipherKeySize
	
	# Generate 208 bytes so expaned key is 240 bytes
	while currentSize < 240:
		# Store the last 4 bytes to t
		for i in range(4):
			t[i] = expandedKey[(currentSize - 4) + i]
		
		# Every 32 bytes apply the core schedule to t
		if (currentSize % cipherKeySize) == 0:
			t = keyScheduleCore(t, rconIter)
			rconIter += 1
		
		# Extra sbox transform as using 256-bit key
		if (currentSize % cipherKeySize) == 16:
			for i in range(4):
				t[i] = sbox[t[i]]
		
		# XOR t with 4 byte block [16, 24, 32] bytes before the end of the
		# current expanded key. These become the next 4 bytes in the expaned key
		for i in range(4):
			expandedKey.append(((expandedKey[currentSize - cipherKeySize]) ^ (t[i])))
			currentSize += 1
	
	return expandedKey

def subBytes(state):
	'''sbox transform on each value in state table'''
	for i in range(len(state)):
		state[i] = sbox[state[i]]

def subBytesInv(state):
	'''Inverse of subBytes - uses sboxInv'''
	for i in range(len(state)):
		state[i] = sboxInv[state[i]]

def addRoundKey(state, roundKey):
	'''XOR each byte of roundKey with the state table'''
	for i in range(len(state)):
		state[i] = state[i] ^ roundKey[i]

def galoisMult(a, b):
	'''Galois Multiplication
	https://en.wikipedia.org/wiki/Finite_field_arithmetic#Program_examples'''
	p = 0
	hiBitSet = 0
	for i in range(8):
		if (b & 1) == 1:
			p ^= a
		hiBitSet = a & 0x80
		a <<= 1
		if hiBitSet == 0x80:
			a ^= 0x1b
		b >>= 1
	return p % 256

def mixColumn(column):
	'''Performs rijndael mix columns operation
	https://en.wikipedia.org/wiki/Rijndael_mix_columns'''
	temp = copy(column)
	column[0] = galoisMult(temp[0],2) ^ galoisMult(temp[3],1) ^ \
				galoisMult(temp[2],1) ^ galoisMult(temp[1],3)
	column[1] = galoisMult(temp[1],2) ^ galoisMult(temp[0],1) ^ \
				galoisMult(temp[3],1) ^ galoisMult(temp[2],3)
	column[2] = galoisMult(temp[2],2) ^ galoisMult(temp[1],1) ^ \
				galoisMult(temp[0],1) ^ galoisMult(temp[3],3)
	column[3] = galoisMult(temp[3],2) ^ galoisMult(temp[2],1) ^ \
				galoisMult(temp[1],1) ^ galoisMult(temp[0],3)

def mixColumnInv(column):
	'''Inverse of mixColumn'''
	temp = copy(column)
	column[0] = galoisMult(temp[0],14) ^ galoisMult(temp[3],9) ^ \
				galoisMult(temp[2],13) ^ galoisMult(temp[1],11)
	column[1] = galoisMult(temp[1],14) ^ galoisMult(temp[0],9) ^ \
				galoisMult(temp[3],13) ^ galoisMult(temp[2],11)
	column[2] = galoisMult(temp[2],14) ^ galoisMult(temp[1],9) ^ \
				galoisMult(temp[0],13) ^ galoisMult(temp[3],11)
	column[3] = galoisMult(temp[3],14) ^ galoisMult(temp[2],9) ^ \
				galoisMult(temp[1],13) ^ galoisMult(temp[0],11)

def mixColumns(state):
	'''Applies the mixColumn function to each column in the state table'''
	for i in range(4):
		column = []
		# Picks elements which lie in column
		for j in range(4):
			column.append(state[j*4+i])
		
		mixColumn(column)
		
		# Transfere the elements back into the state table
		for j in range(4):
			state[j*4+i] = column[j]

def mixColumnsInv(state):
	'''Inverse of mixColumns'''
	for i in range(4):
		column = []
		# Picks elements which lie in column
		for j in range(4):
			column.append(state[j*4+i])
		
		mixColumnInv(column)
		
		# Transfere the elements back into the state table
		for j in range(4):
			state[j*4+i] = column[j]

def aesRound(state, roundKey):
	'''Applies the four transformations to the state
	https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_cipher'''
	subBytes(state)
	shiftRows(state)
	mixColumns(state)
	addRoundKey(state, roundKey)

def aesRoundInv(state, roundKey):
	'''Inverse of aesRound - Applies transformations in opposite order'''
	addRoundKey(state, roundKey)
	mixColumnsInv(state)
	shiftRowsInv(state)
	subBytesInv(state)

def createRoundKey(expandedKey, n):
	'''Returns a 16 byte round key based on an expanded key and round number'''
	return expandedKey[(n*16):(n*16+16)]

def passwordToKey(password):
	'''Creates a key (SHA-256) from a password'''
	sha256 = hashlib.sha256()
	sha256.update(password)
	key = []
	for c in list(sha256.digest()):
		key.append(ord(c)) # ord?
	return key

def aesMain(state, expandedKey, numRounds=14):
	'''Performs multiple rounds of AES (14 as 256 bit key)'''
	roundKey = createRoundKey(expandedKey, 0)
	addRoundKey(state, roundKey)
	for i in range(1, numRounds):
		roundKey = createRoundKey(expandedKey, i)
		aesRound(state, roundKey)
	
	# In final round mixColumns is skiped
	roundKey = createRoundKey(expandedKey, numRounds)
	subBytes(state)
	shiftRows(state)
	addRoundKey(state, roundKey)

def aesMainInv(state, expanedKey, numRounds=14):
	'''Inverse of aesMain'''
	# Create round key from last as in reverse
	roundKey = createRoundKey(expandedKey, numRounds)
	addRoundKey(state, roundKey)
	shiftRowsInv(state)
	subBytesInv(state)
	for i in range(numRounds-1,0,-1):
		roundKey = createRoundKey(expandedKey, i)
		aesRoundInv(state, roundKey)
	# In final round mixColumns is skiped
	roundKey = createRoundKey(expandedKey, 0)
	addRoundKey(state, roundKey)

def aesEncrypt(plaintext, key):
	'''Encrypts a single block of plaintext'''
	block = copy(plaintext)
	expandedKey = expandKey(key)
	aesMain(block, expandedKey)
	return block

def aesDecrypt(ciphertext, key):
	'''Decrypts a single block of ciphertext'''
	block = copy(ciphertext)
	expandedKey = expandKey(key)
	aesMainInv(block, expandedKey)
	return block

def getBlocks(text): #TODO: for File input only?
	'''Returns a 16 byte block from text'''
	blocks = []
	for i in range(0, len(text), 16): #TODO: check not -15
		print(i)
		block = text[i:i+16]
		if len(block) < 16:
			padChar = bytes([16 - len(block)])
			while len(block) < 16:
				block += padChar
		blocks.append(block)
	return blocks

def getBlock(fp):
	raw = fp.read(16)
	# reached end of file
	if len(raw) == 0:
		return ""
	# container for list of bytes
	block = []
	for c in list(raw):
		block.append(ord(c)) #TODO: ord?
		# if the block is less than 16 bytes, pad the block
		# with the string representing the number of missing bytes
	if len(block) < 16:
		padChar = 16-len(block)
		while len(block) < 16:
			block.append(padChar)
	return block


'''
def encrypt(text, password):
	\'''Encrypts text of arbitray length\'''
	outFile = open('out.aes', 'w')
	block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	ciphertext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	# Initialization Vector
	IV = []
	for i in range(16):
		IV.append(randint(0,255))
	
	aesKey = passwordToKey(password)
	
	# Write IV to outFile
	for byte in IV:
		outFile.write(chr(byte))
	
	textByteSize = len(text)
	
	# Encrpt each block
	firstRound = True
	blocks = getBlocks(text)
	for block in blocks:
		if firstRound:
			blockKey = aesEncrypt(IV, aesKey)
			firstRound = False
		else:
			blockKey = aesEncrypt(blockKey, aesKey)
		
		for i in range(16):
			ciphertext[i] = block[i] ^ blockKey[i]
		
		for c in ciphertext:
			outFile.write(chr(c))
	
	if (textByteSize % 16) == 0:
		outFile.write(16*chr(16))
	outFile.close()
'''

def encrypt(myInput, password, outputfile=None):
	block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # plaintext
	ciphertext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # ciphertext
    # Initialization Vector
	IV = []
	for i in range(16):
		IV.append(randint(0, 255))
    
    # convert password to AES 256-bit key
	aesKey = passwordToKey(password)
    
    # create handle for file to be encrypted
	fp = open(myInput, "rb")
    
    # create handle for encrypted output file
	outfile = open(outputfile,"w")
    
    # write IV to outfile
	for byte in IV:
		outfile.write(chr(byte))
    
    # get the file size (bytes)
    # if the file size is a multiple of the block size, we'll need
    # to add a block of padding at the end of the message
	fp.seek(0,2)
	filesize = fp.tell()
    # put the file pointer back at the beginning of the file
	fp.seek(0)
    
    # begin reading in blocks of input to encrypt
	firstRound = True
	block = getBlock(fp)
	while block != "":
		if firstRound:
			blockKey = aesEncrypt(IV, aesKey)
			firstRound = False
		else:
			blockKey = aesEncrypt(blockKey, aesKey)
        
		for i in range(16):
			ciphertext[i] = block[i] ^ blockKey[i]
        
        # write ciphertext to outfile
		for c in ciphertext:
			outfile.write(chr(c))
        
        # grab next block from input file
		block = getBlock(fp)
    # if the message ends on a block boundary, we need to add an
    # extra block of padding
	if filesize % 16 == 0:
		outfile.write(16*chr(16))
    # close file pointers
	fp.close()
	outfile.close()

def decrypt(password):
	inFile = open('out.aes', 'rb')
	block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	plaintext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	
	message = ""
	
	aesKey = passwordToKey(password)
	
	IV = getBlock(inFile)
	print([hex(n) for n in IV])
	inFile.seek(0, 2)
	fileSize = inFile.tell()
	inFile.seek(16)
	
	# Encrpt each block
	firstRound = True
	block = getBlock(inFile)
	while block != "":
		if firstRound:
			blockKey = aesEncrypt(IV, aesKey)
			firstRound = False
		else:
			blockKey = aesEncrypt(blockKey, aesKey)
		
		for i in range(16):
			plaintext[i] = block[i] ^ blockKey[i]
		
		if inFile.tell() == fileSize:
			plaintext = plaintext[0:-(plaintext[-1])]
		
		block = getBlock(inFile)
		
		message += "".join([chr(c) for c in plaintext])
	
	inFile.close()
	print(message)

password ="a"
encrypt('input.txt', password, 'out.aes')
decrypt(password)
	
	