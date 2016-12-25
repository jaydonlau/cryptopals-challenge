from binascii import unhexlify, hexlify
from base64 import b64encode, b64decode
from Crypto.Util.strxor import strxor, strxor_c
from Crypto.Cipher import AES

import heapq
import itertools

SCHEME = 'utf-8'

# Challenge 1: Convert hex to base64
def c1_hex_str_to_base64(s):
	# hex to binary
	bin_seq = unhexlify(s)
	# binary to base 64
	b64 = b64encode(bin_seq)
	return b64.decode(SCHEME)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# Challenge 2: Fixed XOR
# 	take two equal length buffers and produce XOR combination
def c2_fixed_xor(b1, b2):
	bin_b1 = unhexlify(b1)
	bin_b2 = unhexlify(b2)

	fixed_xor = strxor(bin_b1, bin_b2)
	hex_fixed_xor = hexlify(fixed_xor)
	return hex_fixed_xor.decode(SCHEME)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# Challenge 3: Single-byte XOR cipher
# 	s is XOR'ed against a single character, decrypt message
def c3_single_byte_xor_cipher(s):
	return c3_single_byte_xor_cipher_with_score(s)[1].decode(SCHEME)

def c3_frequency_score(s):
	# taken from: https://en.wikipedia.org/wiki/Letter_frequency
	char_frequencies = {
		'a': 0.08167,
		'b': 0.01492,
		'c': 0.02782,
		'd': 0.04253,
		'e': 0.12702,
		'f': 0.02228,
		'g': 0.02015, 
		'h': 0.06094,
		'i': 0.06966,
		'j': 0.00153,
		'k': 0.00772,
		'l': 0.04025,
		'm': 0.02406,
		'n': 0.06749,
		'o': 0.07507,
		'p': 0.01929,
		'q': 0.00095,
		'r': 0.05987,
 		's': 0.06327,
 		't': 0.09056,
 		'u': 0.02758,
 		'v': 0.00978,
 		'w': 0.02360,
		'x': 0.00150,
		'y': 0.01974,
 		'z': 0.00074,
	    ' ': 0.13 
	}
	score = 0
	for char in s:
		c = chr(char).lower()
		if c in char_frequencies:
			score += char_frequencies[c]
	return score

def c3_single_byte_xor_cipher_with_score(s):
	top_message = ''
	top_char = -1
	top_score = 0
	for i in range(256):
		s_xored = strxor_c(s, i)
		score = c3_frequency_score(s_xored)
		if score > top_score:
			top_score = score
			top_char = i
			top_message = s_xored
	return (top_char, top_message)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# Challenge 4: Detect single-character XOR
# 	output the one 60-character string in 4.txt that is encrypted by single-character XOR
def c4_detect_single_character_xor(file_name):
	return c4_detect_single_character_xor_with_score(file_name)[1].decode(SCHEME)

def c4_detect_single_character_xor_with_score(file_name):
	f = open(file_name)
	top_score = -1
	top_message = ''
	for line in f:
		if line[-1] == '\n':
			line = line[:-1]
		unhex_line = unhexlify(line)
		message = c3_single_byte_xor_cipher_with_score(unhex_line)
		score = c3_frequency_score(message[1])
		if score > top_score:
			top_score = score
			top_message = message
	f.close()
	return top_message

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# Challenge 5: Implement repeating-key XOR
def c5_repeating_key_xor_print(s, key):
	cipher = c5_repeating_key_xor(s.encode(SCHEME), key.encode(SCHEME))
	return hexlify(cipher).decode(SCHEME)

def c5_repeating_key_xor(s, key):
	iterator = 0
	cipher = []
	for byte in s:
		byte_k = key[iterator]
		cipher.append(byte ^ byte_k)
		iterator = (iterator + 1) % len(key)
	cipher_bytes = bytes(cipher)
	return cipher_bytes

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# Challenge 6: Break repeating-key XOR
def c6_break_repeating_xor_print(file_name):
	return(c6_break_repeating_xor(file_name)[1].decode(SCHEME))
	

def c6_break_repeating_xor(file_name):

	# returns number of different bits of two equal length strings
	# 	hamming_distance(b'this is a test, b'wokka wokka!!!) -> 37
	def hamming_distance(s1, s2):
		hex_f_xor = hexlify(strxor(s1, s2))
		bin_f_xor = bin(int(hex_f_xor, base=16))
		return bin_f_xor.count("1")

	def normalizedEditDistance(x, k):
	    blocks = [x[i:i+k] for i in range(0, len(x), k)][0:4]
	    pairs = list(itertools.combinations(blocks, 2))
	    scores = [getHammingDistance(p[0], p[1])/float(k) for p in pairs][0:6]
	    return sum(scores) / len(scores)
	
	# returns n smallest normalized hamming distance key sizes
	def get_n_smallest_key_size(cipher_text, n):
		key_sizes = []
		for i in range(2, 41):
			blocks = [cipher_text[j:j+i] for j in range(0, len(cipher_text), i)][:4]
			pairs = list(itertools.combinations(blocks, 2))
			normalized_score = 0
			for p in pairs:
				normalized_score += (hamming_distance(p[0], p[1])) / i
			normalized_score = normalized_score / len(pairs)
			key_sizes.append((normalized_score, i))
		return heapq.nsmallest(n, iter(key_sizes), key=lambda t: t[0])	

	f = open(file_name)
	lines = f.read()
	cipher_text = b64decode(lines)
	smallest_three_ks = get_n_smallest_key_size(cipher_text, 3)
	key_size = smallest_three_ks[0][1]

	blocks = [cipher_text[i:i+key_size] for i in range(0, len(cipher_text), key_size)]
	t_blocks = [[] for i in range(key_size)]
	for block in blocks:
		for i in range(len(block)):
			t_blocks[i].append(block[i])

	array_key = [c3_single_byte_xor_cipher_with_score(bytes(block))[0] for block in t_blocks]
	key = bytes(array_key)
	decrypt = c5_repeating_key_xor(cipher_text, key)

	f.close()
	return (key, decrypt)

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #

# Challenge 7: AES in ECB mode
def c7_decrypt_AES_ECB(file_name, key):
	f = open(file_name)
	lines = f.read()
	cipher_text = b64decode(lines)
	key = key.encode(SCHEME)
	cipher = AES.new(key, AES.MODE_ECB)

	f.close()
	return cipher.decrypt(cipher_text)

