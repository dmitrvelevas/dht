import hashlib
import rsa
import socket

def sender (addr, message):
    sock = socket.socket()
    sock.connect(('localhost', addr))
    sock.send(message)
    print ('successfully sent to ' + str(addr))
	
def xor (first, second):
	hash_first = int((hashlib.sha1(first)).hexdigest(), base=16)
	hash_second = int((hashlib.sha1(second)).hexdigest(), base=16)
	return hash_first^hash_second

def nearest (node_list, publickey_pem):

	#print (node_list)
	xor_list = []
	
	for i in node_list:
		xor_list.append(xor(i[1], publickey_pem))
		
	minimum = min(xor_list[1:])
	index = xor_list.index(minimum)
	
	return node_list[index][0] #ip адрес, соответствующий "ближайшему" ключу

def load_node_list (filename, empty_list, publickey):

	empty_list.clear()
	empty_list = [[0, b'', 0]]	
	bool = True
	with open(filename, 'rb') as nodefile:
		for line in nodefile:
			if bool:
				buffer = [int(line), '', 0]
				bool = False
			else:
				buffer[1] = ((line.replace(b'\\n', b'\n')).replace(b'\r\n', b'')).replace(b'\r', b'') #приводим ключи к единому формату
				buffer[2] = xor(buffer[1], bytes(publickey.save_pkcs1('PEM')))
				bool = True
				empty_list.append(buffer)
				
	return empty_list
	
def load_keys (pubfile, privfile):    #Инициализация ключей. Возвращает список [public, private]
	try:

		with open(pubfile, 'rb') as public_file:
			publickey = rsa.PublicKey.load_pkcs1(public_file.read(), 'PEM')
			
		with open(privfile, 'rb') as private_file:
			privatekey = rsa.PrivateKey.load_pkcs1(private_file.read(), 'PEM')
			

	except FileNotFoundError:

		(publickey, privatekey) = rsa.newkeys(1024)
		
		with open(pubfile, 'wb') as public_file:
			public_file.write(bytes(publickey.save_pkcs1( 'PEM')))

		with open(privfile, 'wb') as private_file:
			private_file.write(bytes(privatekey.save_pkcs1('PEM')))
	
	return	[publickey, privatekey]