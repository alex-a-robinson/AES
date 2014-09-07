#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .byteManipulation import *
from random import randint

class AES():
	
	def __init__(self):
		self.password = None
		self.plaintextFilePath = None
		self.ciphertextFilePath = None
		self.plaintext = None
		self.ciphertext = None
				
	def encrypt(self):
		block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # plaintext
		ciphertext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0] # ciphertext
	    # Initialization Vector
		IV = []
		for i in range(16):
			IV.append(randint(0, 255))

	    
		try:
			# convert password to AES 256-bit key
			aesKey = passwordToKey(self.password)
		except TypeError:
			raise Exception(self.password, "A password must be set")
			

		if self.plaintextFilePath != None:
	    	# create handle for file to be encrypted
			fp = open(self.plaintextFilePath, "rb")
		
		if self.ciphertextFilePath != None:
	    	# create handle for encrypted output file
			outfile = open(self.ciphertextFilePath,"w")

	    # write IV to outfile
		for byte in IV:
			outfile.write(chr(byte))

	    # get the file size (bytes)
	    # if the file size is a multiple of the block size, we'll need
	    # to add a block of padding at the end of the message
		#fp.seek(0,2)
		#filesize = fp.tell()
	    # put the file pointer back at the beginning of the file
		#fp.seek(0)

	    # begin reading in blocks of input to encrypt
		firstRound = True
		#block = getBlock(fp)
		blocks = getBlocks(self.plaintext)
		for block in blocks:
			print(block)
			if firstRound:
				blockKey = aesEncrypt(IV, aesKey)
				firstRound = False
			else:
				blockKey = aesEncrypt(blockKey, aesKey)

			print(blockKey)
			for i in range(16):
				ciphertext[i] = block[i] ^ blockKey[i]

	        # write ciphertext to outfile
			for c in ciphertext:
				outfile.write(chr(c))

	        # grab next block from input file
			#block = getBlock(fp)
	    # if the message ends on a block boundary, we need to add an
	    # extra block of padding
		#if filesize % 16 == 0:
		#	outfile.write(16*chr(16))
	    # close file pointers
		#fp.close()
		outfile.close()

	def decrypt(self):
		inFile = open(self.ciphertextFilePath, 'rb')
		block = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
		plaintext = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

		message = ""

		aesKey = passwordToKey(self.password)

		IV = getBlock(inFile)
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
		
def do():
	a = AES()
	a.password = "testing".encode("utf-8")
	a.plaintext = "input.txtdsafasdfsdfj;ldkfj;lsdkjkjf"
	a.ciphertextFilePath = "out.aes"
	a.encrypt()
	a.decrypt()
	