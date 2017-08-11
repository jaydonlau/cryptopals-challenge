import unittest
from set2 import c9_pkcs_7_padding

class CryptoPalsTest(unittest.TestCase):
	def test_set2_challenge9(self):
		self.assertEqual(c9_pkcs_7_padding("YELLOW SUBMARINE", 20), "YELLOW SUBMARINE\x04\x04\x04\x04")


if __name__ == "__main__":
	unittest.main()