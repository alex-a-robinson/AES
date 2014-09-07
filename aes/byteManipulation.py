#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .tables import *
from random import randint
from copy import copy
import hashlib

def rotate(word, n):
	"""
	Rotates a word n bytes
	
	# Parameters
		word : byte string
		n : int
		
	# Returns
		byte string
	"""
	return word[n:] + word[0:n]

def shiftRows(state):
	"""
	Shifts bytes to the left for each row in state
	
	# Parameters
		state : 4x4 nested array
		
	# See Also
		shiftRowsInv()
	"""
	for i in range(4):
		state[i*4:i*4+4] = rotate(state[i*4:i*4+4], i)

def shiftRowsInv(state):
	"""
	Performs the inverse of shiftRows()
	Shifts bytes to the right for each row in state
	
	# Parameters
		state : 4x4 nested array
		
	# See Also
		shiftRows()
	"""
	for i in range(4):
		state[i*4:i*4+4] = rotate(state[i*4:i*4+4], -i)

def keyScheduleCore(word, i):
	"""
	Generates the sub keys for this round
	
	# Parameters
		word : byte string
		i : int #TODO: ??
		
	# Returns
		A list of sub keys
	"""
	word = rotate(word, 1) # rotate word 1 byte left
	newWord = []
	for byte in word: # sbox substitution for all bytes in word
		newWord.append(sbox[byte])
	newWord[0] = newWord[0] ^ rcon[i] # Xor rcon[i] with first byte of word
	return newWord
		
def expandKey(cipherKey):
	"""
	Expands a 256-bit cipher key into 240-byte key which each round key is derived from
	
	# Parameters
		cipherKey : byte string
		
	# Returns
		byte string
	"""
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
	"""
	sbox transform on each value in state table

	# Parameters
		state : 4x4 nested array

	# See Also
		subBytesInv()
	"""
	
	for i in range(len(state)):
		state[i] = sbox[state[i]]

def subBytesInv(state):
	"""
	Inverse of subBytes
	uses sboxInv table instead of sbox

	# Parameters
		state : 4x4 nested array

	# See Also
		subBytes()
	"""
	for i in range(len(state)):
		state[i] = sboxInv[state[i]]

def addRoundKey(state, roundKey):
	"""
	XOR each byte of roundKey with the state table

	# Parameters
		state : 4x4 nested array
		roundKey : #TODO:?
	"""
	for i in range(len(state)):
		state[i] = state[i] ^ roundKey[i]

def galoisMult(a, b):
	"""
	Performs galois multiplication on a and b

	# Parameters
		a, b : #TODO: ?
		
	# Returns
		#TODO: ?
		
	# Notes
		https://en.wikipedia.org/wiki/Finite_field_arithmetic#Program_examples
	"""
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
	"""
	Performs rijndael mix columns operation

	# Parameters
		column : an array which is a column of the state table 
	
	# See Also
		mixColumnInv()
	
	# Notes
		https://en.wikipedia.org/wiki/Rijndael_mix_columns
	"""
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
	"""
	Performs the inverse of mixColumn

	# Parameters
		column : an array which is a column of the state table 
	
	# See Also
		mixColumn()
	
	# Notes
		https://en.wikipedia.org/wiki/Rijndael_mix_columns
	"""
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
	"""
	Applies the mixColumn function to each column in the state table

	# Parameters
		state : 4x4 nested array
	
	# See Also
		mixColumnsInv()
	"""
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
	"""
	Performs the inverse of mixColumns
	Applies the mixColumnInv function to each column in the state table

	# Parameters
		state : 4x4 nested array
	
	# See Also
		mixColumns()
	"""
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
	"""
	Applies the four transformations to the state for a single round

	# Parameters
		state : 4x4 nested array
		roundKey : #TODO: ?
	
	# See Also
		aesRoundInv()
	
	# Notes
		https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_cipher
	"""
	subBytes(state)
	shiftRows(state)
	mixColumns(state)
	addRoundKey(state, roundKey)

def aesRoundInv(state, roundKey):
	"""
	Inverse of aesRound
	Applies transformations in opposite order

	# Parameters
		state : 4x4 nested array
		roundKey : #TODO: ?
	
	# See Also
		aesRound()
	
	# Notes
		https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_cipher
	"""
	addRoundKey(state, roundKey)
	mixColumnsInv(state)
	shiftRowsInv(state)
	subBytesInv(state)

def createRoundKey(expandedKey, n):
	"""
	Returns a 16 byte round key based on an expanded key and round number

	# Parameters
		expandedKey : #TODO: ?
		n : #TODO: ?
		
	# Returns
		#TODO: ?
	"""
	return expandedKey[(n*16):(n*16+16)]

def passwordToKey(password):
	"""
	Creates a key (SHA-256) from a password'

	# Parameters
		password : string
		
	# Returns
		A 32 byte string
	"""
	sha256 = hashlib.sha256()
	sha256.update(password)
	key = []
	for c in list(sha256.digest()):
		key.append(ord(c)) # ord?
	return key

def aesMain(state, expandedKey, numRounds=14):
	"""
	Performs multiple rounds of AES (14 as 256 bit key)

	# Parameters
		state : 4x4 nested array
		expandedKey : #TODO: ?
		numRounds : int
		
	# See Also
		aesMainInv()
	"""
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
	"""
	Performs the inverse of aesMain
	Performs multiple rounds of AES in reverse (14 as 256 bit key)

	# Parameters
		state : 4x4 nested array
		expandedKey : #TODO: ?
		numRounds : int
		
	# See Also
		aesMain()
	"""
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
	"""
	Encrypts a single block of plaintext

	# Parameters
		plaintext : byte string
		key : #TODO: ?
		
	# Returns
		16 byte block of ciphertext
		
	# See Also
		aesDecrypt()
	"""
	block = copy(plaintext)
	expandedKey = expandKey(key)
	aesMain(block, expandedKey)
	return block

def aesDecrypt(ciphertext, key):
	"""
	Performs the inverse of aesEncrypt
	Decrypts a single block of ciphertext

	# Parameters
		ciphertext : byte string
		key : #TODO: ?
		
	# Returns
		16 byte block of plaintext
		
	# See Also
		aesEncrypy
	"""
	block = copy(ciphertext)
	expandedKey = expandKey(key)
	aesMainInv(block, expandedKey)
	return block

def getBlocks(text): #TODO: for File input only?
	"""
	Returns a 16 byte block from text

	# Parameters
		text : byte string
		
	# Returns
		List of 16 byte blocks
	"""
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
	"""
	Returns a 16 byte block from text

	# Parameters
		fp : readable file object
		
	# Returns
		a 16 byte block
	"""
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

