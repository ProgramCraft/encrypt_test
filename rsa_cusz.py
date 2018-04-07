# -*- coding: utf-8 -*-
import os
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from datetime import datetime
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5

g_hash_key = None
g_cipher_path = 'factory_cipher.peppa'
g_orien_bin = 'binary_file.bin'

def gen_custz_tool_key():
	random_generator = Random.new().read
	rsa = RSA.generate(2048,random_generator)
	private_pem = rsa.exportKey()
	with open('custz_private.pem','wb') as f:
		f.write(private_pem)
	public_pem = rsa.publickey().exportKey()
	with open('custz_public.pem','wb') as f:
		f.write(public_pem)
	
def gen_a_hash_key():#related with curr time and local machine name
	timeNow = datetime.now()
	# print(timeNow)
	userName = os.path.expanduser('~').split('\\')[-1]
	# print(userName)
	h = MD5.new()
	hash_obj = str(timeNow)+userName
	h.update(hash_obj.encode('utf-8'))
	key = h.hexdigest()
	#print(key)
	return key


def hash_key_generate():
	global g_hash_key
	g_hash_key = gen_a_hash_key()
	with open('custz_aes.bin','wb') as f:
		f.write(g_hash_key)
		f.close()

def hash_key_load():
	global g_hash_key	
	g_hash_key = '673d7665c4a7b79b1e361dd2f5fb70ee'
	
def generate_encrypt_bin_from_orien():
	global g_hash_key,g_cipher_path
	bin_file = open(g_orien_bin)
	orien_text = bin_file.read()
	bin_file.close()
	cipher = AES.new(g_hash_key,AES.MODE_ECB)
	cipherText = cipher.encrypt(orien_text)
	#print(cipherText)
	cipher_file = open(g_cipher_path,'wb')
	cipher_file.write(cipherText)
	cipher_file.close()


def load_encrypt_bin_then_decrypt():
	global g_hash_key,g_cipher_path
	read_file = open(g_cipher_path,'rb')
	read_data = read_file.read()
	read_file.close()
	decipher = AES.new(g_hash_key,AES.MODE_ECB)
	decipherText = decipher.decrypt(read_data).decode('utf-8')
	print(decipherText)

	return decipherText

def get_custz_bin_data():
	bin_data = None
	with open(g_orien_bin) as f:
		bin_data = f.read()
	return bin_data.encode()

def get_orien_bin_sign():
	sign_data = None
	orien_data = get_custz_bin_data()
	with open('custz_private.pem') as f:
		key = f.read()
		rsakey = RSA.importKey(key)
		signer = Signature_pkcs1_v1_5.new(rsakey)
		digest = SHA.new()
		digest.update(orien_data)
		sign_data = signer.sign(digest)
	return sign_data

if __name__ == '__main__':
	# gen_custz_tool_key()
	# hash_key_generate()
	
	hash_key_load()
	generate_encrypt_bin_from_orien()
	sign_data = get_orien_bin_sign()
	orien_data = load_encrypt_bin_then_decrypt().encode()
	with open('custz_public.pem') as f:
		key = f.read()
		rsakey = RSA.importKey(key)
		verifier = Signature_pkcs1_v1_5.new(rsakey)
		digest = SHA.new()
		digest.update(orien_data)
		is_verify = verifier.verify(digest,sign_data)
		if is_verify is True:
			print(True)
		else:
			print(False)

		
