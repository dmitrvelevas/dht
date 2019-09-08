import rsa
import pyAesCrypt
import foo
import socket
import threading
import time
import queue
import os
import random

my_ip = 9090	#наш адрес

def list_updater ():
	
	global node_list
	global my_ip
	
	while True:
		check_list = []
		
		if len(node_list[1:]) < 6:
			check_list = node_list[1:]
		else:
			length = len(node_list)
			print('Длина списка ' + str(length))
			n = []
			for i in range(5):	
				a = random.randrange(1, length-1, 1)	
				while (a in n):
					a = random.randrange(1, length-1, 1)		
				n.append(a)
				print(a)
			for i in n:
				check_list.append(node_list[i])
				
			print(n)
				

		for i in check_list:
			item = (b'1'+ bytes(str(my_ip), 'utf-8') + bytes(publickey.save_pkcs1('PEM')) + bytes(str(i[0]), 'utf-8')) #str(i[0]) - адрес получателя 
			socket_queue.put([0, item])																				# это поле не дойдёт до получателя
			print('list_updater: сформирован и отправлен в очередь на отправку пакет' )
			
		time.sleep(10)
		
		prototype_list = [[0, b'', 0]] 	
		
		for i in range(10):
			if receiver_to_updater.empty() == True:
				break
			buf = receiver_to_updater.get()
			buf = buf[1:] #отделяем служебный символ
			step = 0
			for j in range(int(len(buf)/255)):
				ipaddr = int(buf[(step):(step+4)])
				keyaddr = buf[(step+4):(step+255)]
				
				xor = foo.xor(keyaddr, bytes(publickey.save_pkcs1('PEM')))
				if xor!=0:
					prototype_list.append([ipaddr, 
										   keyaddr, 
										   xor])
				step += 255
				
		#print(prototype_list)
		
		
		prototype_list += node_list[1:] #прибавляем старые значения к новому списку
		
		#прибавляем потенциально новые ноды		
		while (former_to_updater.empty() == False):
			prototype_list.append(former_to_updater.get())
			
		#начинаем сортировку и удаление дублей
		def sort_col(i):
			return i[2]
		
		prototype_list.sort(key = sort_col)
		
		print('Список после сортировки')
		print(prototype_list)
		
		new_prototype_list = [] 
		
		for i in range(int(len(prototype_list))-1):
			#print(prototype_list[i][1])
			if (prototype_list[i][1]!=prototype_list[i+1][1]):
				new_prototype_list.append(prototype_list[i+1])
				#print('Забираем')

		print('\nСписок после удаления дублей\n')
		print(new_prototype_list)
		
		# выбираем 60 ближайших и 4 самых дальних адреса
		size = len(new_prototype_list)
		if size >= 64:
			final_list = new_prototype_list[:59]
			final_list.append(new_prototype_list[size-2])
			final_list.append(new_prototype_list[size-3])
			final_list.append(new_prototype_list[size-4])
			final_list.append(new_prototype_list[size-5])
		else:
			final_list = new_prototype_list
		
		#пишем новый список в файл		
		with open('node_list.txt', 'w') as list:
			for i in final_list:
				list.write(str(i[0]) + '\n')
				list.write((i[1].replace(b'\n', b'\\n')).decode('utf-8') + '\n')	
		try:
			with open('node_list.txt', 'rb+') as filehandle:
				filehandle.seek(-1, os.SEEK_END)
				filehandle.truncate()	
		except OSError:
			print('final_list пуст, поэтому запись невозможна')
		
		#перезаписываем node_list
		with lock:
			node_list = [[0, b'', 0]] + final_list
			
		print('new list\n')	
		print(node_list)
					
def former (): #формирует ответы на запросы списка

	while True:
	
		check_list = []
		
		message = receiver_to_former.get()
		ipaddr = message[1:5] # не преобразуем в инт, так как потом всё равно складывать
		
		
		print('_______________________________________________\n\n')
		print('Получено сообщение на запрос списка от ноды' + str(message[1:5]))
		print(message[5:256])
		print('\n\n_______________________________________________')
		
		new_node_pub_key = message[5:256]
		new_node_description = [int(ipaddr),new_node_pub_key, foo.xor(new_node_pub_key, bytes(publickey.save_pkcs1('PEM')))]
		former_to_updater.put(new_node_description)
		print('------------')
		print(new_node_description)
		print('------------')
		
		if len(node_list[1:]) <= 10:
			check_list = node_list[1:]
			
		else:
			length = len(node_list)
			n = []
			for i in range(10):	
				a = random.randrange(1, length-1, 1)	
				while (a in n):
					a = random.randrange(1, length-1, 1)		
				n.append(a)
			for i in n:
				check_list.append(node_list[i])
			
			print('Будет отправлено\n')
			for i in check_list:
				print(i[0])
		
		answer = b'2'
		for i in check_list:
			answer += bytes(str(i[0]), 'utf-8') + i[1]
		answer += ipaddr # я же говорил
		socket_queue.put([0, answer])
		print('former: сформирован и отправлен в очередь на отправку пакет' )
					
def socket_income ():
	
	global my_ip
	sock = socket.socket()
	sock.bind(('', my_ip))
	sock.listen(1)
	
	while True:
		conn, addr = sock.accept()
		
		data = b''
		while True:
			get = conn.recv(1024)
			if not get:
				break
			data += get

		if data[0:1] == b'0': # обычное сообщение
			socket_queue.put([1, data])
			print('------получено сообщение для пересылки' )
		elif data[0:1] == b'1': # запрос списка у нашей ноды
			receiver_to_former.put(data)
			print('------получен former' )
		elif data[0:1] == b'2': # получен список от соседней ноды
			receiver_to_updater.put(data)
			print('------получен updater' )
			
		conn.close()
	
def socket_outcome ():
	
	global node_list
	while True:
		data = socket_queue.get()
		data = data[1] #так как из очереди выходит кортеж
		
		if data[0:1] == b'0':
			if bytes(publickey.save_pkcs1('PEM'))==data[1:252]:
				print(data)
			else:
				flag = True
				while flag:
					#Ищем подходящего кандидата
					addr = foo.nearest(node_list, data[1:252])
					try:
						#отправка сообщения
						foo.sender(addr, data)
						print('')
						print(data)
						print('')
						print('Пересылка сообщения')
						flag = False
						
					except ConnectionError:
						print('Нода' + str(addr) + 'не отвечает')
						for i in range(int(len(node_list))):
							if (node_list[i][0] == addr):
								with lock:
									node_list.pop(i)
								break			
				
		elif data[0:1] == b'1':
			try:
				addr = int(data[-4:])
				message = data[:-4]
				foo.sender(addr, message)
				print('Отправка запроса на список')
				
			except ConnectionError:
				print('Нода' + str(addr) + 'не отвечает')
				for i in range(int(len(node_list))):
					if (node_list[i][0] == int(addr)):
						with lock:
							node_list.pop(i)
						#print(node_list)
						break
			
		elif data[0:1] == b'2':
			try:
				addr = int(data[-4:])
				message = data[:-4]
				foo.sender(addr, message)
				print('Отправка списка')
				
			except ConnectionError:
				print('Нода' + str(addr) + 'не отвечает')

lock = threading.Lock()	
	
#Инициализация очередей 
socket_queue = queue.PriorityQueue() #очередь с приоритетом на отправку сообщений
receiver_to_updater = queue.Queue() #очередь пакетов для обновления собственного списка
receiver_to_former = queue.Queue() #очередь к формирователю пакетов списка
former_to_updater = queue.Queue() #очередь от формирователя к обновлятелю


#Инициализация ключей
keys = foo.load_keys ('pub.txt', 'priv.txt')
publickey = keys[0]
privatekey = keys[1]

print (bytes(publickey.save_pkcs1('PEM')))

#грузим список нод	
node_list = []
node_list = foo.load_node_list('node_list.txt', node_list, publickey)
print (node_list)

#запускаем потоки

updater = threading.Thread(target=list_updater, name = 'Thread0')
updater.start()

income = threading.Thread(target=socket_income, name = 'Thread1')
income.start()

outcome = threading.Thread(target=socket_outcome, name = 'Thread2')
outcome.start()

former = threading.Thread(target=former, name = 'Thread3')
former.start()

