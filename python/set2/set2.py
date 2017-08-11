from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from set1 import 

SCHEME = 'utf-8'

# Taken from http://japrogbits.blogspot.ca/2011/02/using-encrypted-data-between-python-and.html
class PKCS7Encoder(object):
	def __init__(self, k=16):
		self.k = k

	## @param text The padded text for which the padding is to be removed.
	# @exception ValueError Raised when the input padding is missing or corrupt.
	def PKCS7decode(self, text):
		nl = len(text)
		val = int(hexlify(text[-1]), 16)
		l = nl - val
		return text[:l]

	## @param text The text to encode.
	def PKCS7encode(self, text):
		l = len(text)
		padding_amt = self.k - (l % self.k)
		if padding_amt == 0:
			padding_amt = self.k
		pad = chr(padding_amt)
		return text + pad * padding_amt


# Challenge 9: Implement PKCS#7 Padding
def c9_pkcs_7_padding(block, length):
	encoder = PKCS7Encoder(length)
	pad_block = encoder.PKCS7encode(block)
	return pad_block

# Challenge 10: Implement CBC mode
def c10_cbc_mode(file_name):
	f = open(file_name)
	lines = f.read()
	

print(c10_cbc_mode("10.txt"))
