from binascii import unhexlify
import base64

def hex_str_to_base64(s):
	byte_seq = unhexlify(s)
	return base64.b64encode(byte_seq)
