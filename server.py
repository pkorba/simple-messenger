#! /usr/bin/env python3

import ssl
import socket
import threading
import queue
import re
import logging
from datetime import datetime

logging.basicConfig(handlers=[logging.FileHandler(filename='chatServer.log', encoding='utf-8')], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

HEADER_LENGTH = 14
PROTOCOL_VERSION = 1

ip_address = ""
port = 2900
lock = threading.Lock()
clients = {}
rooms = {}
name_pattern = re.compile(r"^[a-zA-Z0-9_\-\.]{1,32}$")
room_pattern = re.compile(r"^[a-zA-Z0-9_\-]{1,32}$")

def recv(client, length, buf_length):
	"""Odbieranie dowolnej wiadomości - zapewnienia by wiadomość była odebrana w całości

	Args:
		client (socket): socket klienta
		length (int): długość odbieranej wiadomości
		buf_length (int): wielkość bufora (może być mniejsza niż wielkość wiadomości)
	Zwraca:
		message_payload (bytes): zawartość pobranej wiadomości
	"""
	chunks = []
	bytes_received = 0
	while bytes_received < length:
		chunk = client.recv(min(length - bytes_received, buf_length))
		if chunk == b'':
			raise ConnectionError("Zerwano połączenie.")
		chunks.append(chunk)
		bytes_received += len(chunk)
	message_payload =  b''.join(chunks)
	return message_payload


def receive(client):
	"""Odbiera treść wiadomości

	Args:
		client (socket) - socket klienta
	Zwraca:
		protocol_version (int): wersja protokołu
		message_type (str): typ wiadomości
		message_payload (str): treść wiadomości
	"""
	message_header = recv(client, HEADER_LENGTH, HEADER_LENGTH)
	if not len(message_header):
		raise ConnectionError("Zerwano połączenie.")
	protocol_version = int.from_bytes(message_header[:1], byteorder='big', signed=False)
	message_type = message_header[2:12].decode().strip()
	message_length = int.from_bytes(message_header[12:14], byteorder='big', signed=False)
	message_payload = recv(client, message_length, 2048).decode()
	return (protocol_version, message_type.upper(), message_payload)


def prepare_message(message_type, message_payload):
	"""Przygotowuje wiadomość do wysłania dodając nagłówek do treści wiadomości.

	Args:
		message_type (str): typ wiadomości
		message_payload (str): treść wiadomości
	Zwraca:
		(bytes): zakodowana wiadomość z nagłówkiem
	"""
	protocol_version = PROTOCOL_VERSION.to_bytes(2, byteorder='big', signed=False)
	message_payload = message_payload.encode()
	message_length = len(message_payload).to_bytes(2, byteorder='big', signed=False)
	header = message_type.ljust(10, ' ').encode() + message_length
	return protocol_version + header + message_payload

def command_name(client, message_payload, addr):
	"""Obsługuje zmianę pseudonimu przez klienta.

	Args:
		client (socket) - socket klienta
		message_payload (str) - nowy pseudonim klienta
		addr (tuple) - adres klienta
	"""
	new_message_payload = ""
	username = message_payload.strip()
	is_taken = False
	# Sprawdza czy wybrany pseudinim jest już zajęty.
	for v in clients.values():
		if v['name'] == username:
			is_taken = True
	name_match = re.match(name_pattern, username)	# Test zgodności pseudonimu z wymogami.
	if name_match is not None and len(username) <= 32 and not is_taken:
		# Jeśli pseudonim jest OK
		username_change = False
		old_username = clients[client.fileno()]['name']
		if old_username is not None:
			# Zmiana pseudonimu, a nie ustalanie pierwszego.
			username_change = True
		clients[client.fileno()]['name'] = username
		new_message_payload = "11 Pseudonim zaakceptowany."
		new_message = prepare_message("OK", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
		if username_change:
			# Wiadomość informacyjna dla wszystkich w pokoju w przypadku zmiany nazwy jego członka.
			room_name = clients[client.fileno()]['room']
			if room_name is not None:
				new_message_payload = f"Użytkownik {old_username} zmienił nazwę na {username}."
				logging.info(new_message_payload)
				new_message = prepare_message("INFO", new_message_payload)
				for cl in rooms[room_name]:
					clients[cl]['queue'].put(new_message)
				command_users(client, room_name, True)	# Aktualizacja listy użytkowników w klientach.
	elif is_taken:
		new_message_payload = "11 Pseudonim jest już zajęty."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
		logging.info(f"Użytkownik {addr}: ERROR {new_message_payload}")
	else:
		new_message_payload = "12 Niedozwolony pseudonim."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
		logging.info(f"Użytkownik {addr}: ERROR {new_message_payload}")


def command_list(client):
	"""Wysyła do klienta listę istniejących pokoi.

	Args:
		client (socket) - socket klienta
	"""
	new_message_payload = "\n".join(rooms.keys())
	new_message = prepare_message("LIST", new_message_payload)
	clients[client.fileno()]['queue'].put(new_message)


def command_message(client, message_payload, addr):
	"""Wysyła zwykłą wiadomość do pokoju, w którym znajduje się klient.

	Args:
		client (socket) - socket klienta
		message_payload (str) - treść wiadomości
		addr (tuple) - adres klienta
	"""
	room_name = ""
	room_name = clients[client.fileno()]['room']
	if room_name is not None:
		# Jeśli użytkownik jest w pokoju.
		new_message_payload = f"{datetime.now().strftime('%H:%M')} {clients[client.fileno()]['name']}: {message_payload}"
		new_message = prepare_message("MESSAGE", new_message_payload)
		for cl in rooms[room_name]:
			clients[cl]['queue'].put(new_message)
	else:
		# Wiadomości wysyłane poza pokojem są niedozwolone.
		new_message_payload = "21 Serwer otrzymał wiadomość typu MESSAGE, ale klient nie znajduje się w pokoju rozmów."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
		logging.info(f"Użytkownik {addr}: ERROR {new_message_payload}")


def command_users_self(client):
	"""Wysyła do klienta listę użytkowników pokoju, w którym znajduje się klient.

	Args:
		client (socket) - socket klienta
	"""
	new_message_payload = ""
	room_name = clients[client.fileno()]['room']
	if room_name is not None:
		for i in rooms[room_name]:
			new_message_payload += clients[i]['name'] + "\n"
		new_message = prepare_message("USERS", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
	else:
		new_message_payload = "24 Klient nie jest członkiem żadnego pokoju rozmów."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)


def command_join(client, message_payload):
	"""Obsługuje proces dołączania do nowego pokoju przez klienta.

	Args:
		client (socket) - socket klienta
		message_payload (str) - treść wiadomości
	"""
	message_payload = message_payload.strip()
	# Sprawdzenie poprawności nazwy pokoju.
	room_match = re.match(room_pattern, message_payload)
	if room_match is None:
		# Niedozwolona nazwa pokoju
		new_message_payload = "25 Niedozwolona nazwa pokoju."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
	elif clients[client.fileno()]['room'] is None:
		# Można dodać użytkownika do istniejącego/nowego pokoju.
		if message_payload in rooms.keys():
			rooms[message_payload].append(client.fileno())
		else:
			rooms[message_payload] = [client.fileno()]
		clients[client.fileno()]['room'] = message_payload
		# Komunikat o sukcesie dla klienta
		new_message_payload = f"21 {message_payload}"
		new_message = prepare_message("OK", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
		# Wiadomość o dołączeniu dla członków pokoju (oprócz dołączającego)
		new_message_payload = f"{clients[client.fileno()]['name']} dołączył(a) do pokoju."
		new_message = prepare_message("INFO", new_message_payload)
		for cl in rooms[message_payload]:
			if cl != client.fileno():
				clients[cl]['queue'].put(new_message)
		# Zaktualizowana lista użytkowników, wysyłana do każdego członka pokoju.
		command_users(client, message_payload, True)
	else:
		# Użytkownik może się znajdować tylko w jednym pokoju jednocześnie.
		new_message_payload = "22 Klient może znajdować się tylko w jednym pokoju naraz."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)

def command_users(client, room_name, to_self):
	"""Wysyła listę użytkowników znajdującą się w pokoju.

	Args:
		client (socket) - socket klienta
		room_name (str) - nazwa pokoju
		to_self (boolean) - True jeśli wiadomość należy wysłać do wszystkich włącznie z nadawcą,
							False jeśli do wszystkich oprócz nadawcy
	"""
	if room_name is not None:
		new_message_payload = ""
		client_fd = clients[client.fileno()]
		for cl in rooms[room_name]:
			new_message_payload += clients[cl]['name'] + "\n"
		new_message = prepare_message("USERS", new_message_payload)
		for cl in rooms[room_name]:
			if client_fd == cl and not to_self:
				continue
			else:
				clients[cl]['queue'].put(new_message)
	else:
		new_message_payload = "24 Klient nie jest członkiem żadnego pokoju rozmów."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)


def command_leave(client):
	"""Obsługuje proces opuszczania pokoju przez użytkownika.

	Args:
		client (socket) - socket klienta
	"""
	if clients[client.fileno()]['room'] is not None:
		room_name = clients[client.fileno()]['room']
		clients[client.fileno()]['room'] = None
		rooms[room_name].remove(client.fileno())
		# Potwierdzenie opuszczenia dla klienta.
		new_message_payload = "22 Opuszczenie pokoju zakończone powodzeniem."
		new_message = prepare_message("OK", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)
		# Wiadomość o opuszczeniu dla członków pokoju (oprócz opuszczajacego).
		new_message_payload = f"{clients[client.fileno()]['name']} opuścił(a) pokój."
		new_message = prepare_message("INFO", new_message_payload)
		for cl in rooms[room_name]:
			if cl != client.fileno():
				clients[cl]['queue'].put(new_message)
		# Zaktualizowana lista użytkowników dla członków pokoju (oprócz opuszczającego).
		command_users(client, room_name, False)
		if not rooms[room_name]:
			# Pokój jest pusty, należy go usunąć.
			del rooms[room_name]
	else:
		new_message_payload = "24 Użytkownik nie jest członkiem pokoju rozmów."
		new_message = prepare_message("ERROR", new_message_payload)
		clients[client.fileno()]['queue'].put(new_message)


def command_quit(client):
	"""Obsługuje żądanie klienta o rozłączenie się z serwerem.

	Args:
		client (socket) - socket klienta
	"""
	if clients[client.fileno()]['room'] is not None:
		room_name = clients[client.fileno()]['room']
		clients[client.fileno()]['room'] = None
		rooms[room_name].remove(client.fileno())
		new_message_payload = f"{clients[client.fileno()]['name']} wyszedł(ła)."
		new_message = prepare_message("INFO", new_message_payload)
		for cl in rooms[room_name]:
			if cl != client.fileno():
				clients[cl]['queue'].put(new_message)
		# Zaktualizowana lista użytkowników dla członków pokoju.
		command_users(client, room_name, False)
		if not rooms[room_name]:
			# Pokój jest pusty, należy go usunąć.
			del rooms[room_name]
	# Rozłączenie zwyczajne, nieblokujące (command_quit() działa w funkcji, która
	# wcześniej nałożyła blokadę.)
	disconnect_nonblocking(client, client_plain, addr)


def command_unknown(client):
	"""Obsługa wiadomości nieznanego typu.

	Args:
		client (socket) - socket klienta
	"""
	new_message_payload = "23 Nieobsługiwany typ wiadomości."
	new_message = prepare_message("ERROR", new_message_payload)
	clients[client.fileno()]['queue'].put(new_message)


def client_receive(client, client_plain, addr):
	"""Funkcja obsługująca odbieranie wiadomości przez klienta, uruchamiana w nowym wątku.

	Args:
		client (socket): szyfrowany socket klienta
		client_plain (socket) nieszyfrowany socket klienta
		addr (str): adres klienta
	"""
	while True:
		try:
			protocol_version, message_type, message_payload = receive(client)
		except (EOFError, ConnectionError):
			disconnect(client, client_plain, addr)
			break
		if message_type != "MESSAGE":
			# Nie zamieszczać w logach treści prywatnych wiadomości użytkowników.
			print(f"Wiadomość typu {message_type} od klienta {addr}: {message_payload}")
			logging.info(f"Wiadomość typu {message_type} od klienta {addr}: {message_payload}")
		# Zarządzanie typami odebranych wiadomości
		with lock:
			# Nienazwany klient nie ma prawa wywołać innej komendy niż NAME
			if message_type != "NAME" and clients[client.fileno()]['name'] is None:
				command_unknown()
				continue
			elif message_type == "MESSAGE":
				command_message(client, message_payload, addr)
				# Zamieszczać w logach tylko nadawcę wiadomości.
				logging.info(f"Wiadomość typu MESSAGE od klienta {addr}")
			elif message_type == "LIST":
				command_list(client)
			elif message_type == "USERS":
				command_users_self(client)
			elif message_type == "JOIN":
				command_join(client, message_payload)
			elif message_type == "LEAVE":
				command_leave(client)
			elif message_type == "NAME":
				command_name(client, message_payload, addr)
			elif message_type == "QUIT":
				command_quit(client)
				break
			else:
				command_unknown()


def disconnect(client, client_plain, addr):
	"""Obsługuje całkowite rozłączanie klienta od serwera.

	Args:
		client (socket): szyfrowany socket klienta
		client_plain (socket) nieszyfrowany socket klienta
		addr (str): adres klienta
	"""
	fd = client.fileno()
	with lock:
		q = clients.get(fd, None)['queue']
		room_name = clients.get(fd, None)['room']
		user_name = clients.get(fd, None)['name']
		if q:
			# Sygnał dla wątku wysyłającego wiadomości, by zakończyć pracę.
			q.put(None)
			del clients[fd]
		if room_name:
			rooms[room_name].remove(fd)
			new_message_payload = f"{user_name} opuścił(a) pokój."
			new_message = prepare_message("INFO", new_message_payload)
			for cl in rooms[room_name]:
				clients[cl]['queue'].put(new_message)
			# Zaktualizowana lista użytkowników dla członków pokoju (oprócz opuszczającego).
			new_message_payload = ""
			for cl in rooms[room_name]:
				new_message_payload += clients[cl]['name'] + "\n"
			new_message = prepare_message("USERS", new_message_payload)
			for cl in rooms[room_name]:
				clients[cl]['queue'].put(new_message)

			if not rooms[room_name]:
				# Pokój jest pusty, należy go usunąć.
				del rooms[room_name]
	print(f"Klient {addr} rozłączył się.")
	logging.info(f"Klient {addr} rozłączył się.")
	client.close()
	client_plain.close()


def disconnect_nonblocking(client, client_plain, addr):
	"""Obsługuje całkowite rozłączanie klienta od serwera.
	Zakłada wywołanie z wcześniej nałożoną poza funkcją blokadą sekcji krytycznej.
	Zakłada wykonanie w sytuacji nie spowodowanej błędem. Wymaga uprzedniego usunięcia
	użytkownika z listy pokoi i ewentualnego pustego pokoju.

	Args:
		client (socket): szyfrowany socket klienta
		client_plain (socket) nieszyfrowany socket klienta
		addr (str): adres klienta
	"""
	fd = client.fileno()
	q = clients.get(fd, None)['queue']
	if q:
		# Sygnał dla wątku wysyłającego wiadomości, by zakończyć pracę.
		q.put(None)
		del clients[fd]
	print(f"Klient {addr} rozłączył się.")
	logging.info(f"Klient {addr} rozłączył się.")
	client.close()
	client_plain.close()


def client_send(client, client_plain, q, addr):
	"""Funkcja obsługująca odbieranie wiadomości przez klienta, uruchamiana w nowym wątku.

	Args:
		client (socket): szyfrowany socket klienta
		client_plain (socket) nieszyfrowany socket klienta
		q (Queue): kolejka wiadomości klienta
		addr (str): adres klienta
	"""
	while True:
		message = q.get()
		if message is None:
			break
		try:
			client.sendall(message)
		except:
			disconnect(client, client_plain, addr)
			break


if __name__ != "__main__":
	exit(1)

try:
	if socket.has_dualstack_ipv6():
		sock_listener = socket.create_server((ip_address, port), family=socket.AF_INET6, backlog=50, dualstack_ipv6=True)
		logging.info("Obsługa dual-stack włączona")
	else:
		sock_listener = socket.create_server((ip_address, port))
		logging.info("Obsługa dual-stack wyłączona")
except socket.error as e:
	logging.info("Błąd przy tworzeniu gniazda.")
	print("Błąd przy tworzeniu gniazda.")
	exit(1)

address_listener = sock_listener.getsockname()
print(f"Nasłuchiwanie na nowych klientów na {address_listener}")
logging.info(f"Nasłuchiwanie na nowych klientów na {address_listener}")
try:
	while True:
		client_plain, addr = sock_listener.accept()
		client = ssl.wrap_socket(client_plain, server_side=True, certfile="pascert.crt", keyfile="paskey.key", ssl_version=ssl.PROTOCOL_TLSv1_2)
		q = queue.Queue()
		# Przyjęcie klienta
		with lock:
			clients[client.fileno()] = {"name": None,
								"queue": q,
								"room": None}
		thread_receive = threading.Thread(target=client_receive, args=[client, client_plain, addr], daemon=True)
		thread_send = threading.Thread(target=client_send, args=[client, client_plain, q, addr], daemon=True)
		thread_receive.start()
		thread_send.start()
		print(f"Klient o adresie {addr} nawiązał połączenie.")
		logging.info(f"Klient o adresie {addr} nawiązał połączenie.")
except KeyboardInterrupt:
	logging.info("Zakończono działanie programu.")
	print("Zakończono działanie programu.")
	sock_listener.close()
	exit(0)
