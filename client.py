import rsa
import pyAesCrypt
import foo

'''
#Инициализация ключей
keys = foo.load_keys ('a.txt', 'b.txt')
publickey = keys[0]
privatekey = keys[1]


#грузим список нод	
node_list = []
node_list = foo.load_node_list('node_list.txt', node_list)
'''
#формируем сообщение
key_addr = b'-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAIXFFV1V+9QqA+thMFR9wlh1P9acAz2Tqj0FIDsRLYO8RowhbBaGRNZk\n6po4NAdxo4/C1QlbFF0j96iEK6Hx03sz7RVtDB5x/DDpSHbGZ50vkJHdeucvmSIb\nhN1JDkGdTFT60OWu5DAcy9L1B7xCoq0zBBDX96LJP1zkMhec4zyrAgMBAAE=\n-----END RSA PUBLIC KEY-----\n'
txt = b'watsup_guys!!!'
package = b'0' + key_addr + txt
'''
#Ищем подходящего кандидата
addr = foo.nearest(node_list, key_addr)
'''	
#отправка сообщения
foo.sender(9094, package)	










	
'''
sock = socket.socket()
sock.connect(('localhost', 9090))
sock.send(b'hello, world!')

data = sock.recv(1024)
sock.close()
'''







	