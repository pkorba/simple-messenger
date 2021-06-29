#! /usr/bin/env python3

import ssl
import socket
import threading
import PySimpleGUI as sg

server_address = "localhost"
server_port = 2900
HEADER_LENGTH = 14
PROTOCOL_VERSION = 1


def recv(sock, length, buf_length):
	"""Odbieranie dowolnej wiadomości - zapewnienia by wiadomość była odebrana w całości

	Args:
		sock (socket): socket
		length (int): długość odbieranej wiadomości
		buf_length (int): wielkość bufora (może być mniejsza niż wielkość wiadomości)
	Zwraca:
		message_payload (bytes): zawartość pobranej wiadomości
	"""
	chunks = []
	bytes_received = 0
	while bytes_received < length:
		chunk = sock.recv(min(length - bytes_received, buf_length))
		if chunk == b'':
			raise ConnectionError("Zerwano połączenie.")
		chunks.append(chunk)
		bytes_received += len(chunk)
	message_payload =  b''.join(chunks)
	return message_payload

def receive(sock):
	"""Odbiera treść wiadomości

	Args:
		sock (socket) - socket serwera
	Zwraca:
		protocol_version (int): wersja protokołu
		message_type (str): typ wiadomości
		message_payload (str): treść wiadomości
	"""
	message_header = recv(sock, HEADER_LENGTH, HEADER_LENGTH)
	if not len(message_header):
		raise ConnectionError("Zerwano połączenie.")
	protocol_version = int.from_bytes(message_header[:1], byteorder='big', signed=False)
	message_type = message_header[2:12].decode().strip()
	message_length = int.from_bytes(message_header[12:14], byteorder='big', signed=False)
	message_payload = recv(sock, message_length, 2048).decode()
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

def handle_input(server, server_plain, message):
	"""Funkcja służy pobieraniu wiadomości od użytkownika i wysyłaniu ich do serwera.

	Args:
		server (socket) - szyfrowany socket serwera, do którego wysyłane są wiadomości
		server_plain (socket) - nieszyfrowany socket serwera, do którego wysyłane są wiadomości
		message (str) - wiadomość do wysłania
	"""
	if message.lower().startswith("/name"):
		new_message_payload = message.split()
		if len(new_message_payload) >= 2:
			new_message_payload = new_message_payload[1].strip()
			new_message = prepare_message("NAME", new_message_payload)
			try:
				server.sendall(new_message)
			except socket.error:
				sg.popup_error("Błąd: Niepowodzenie w realizacji polecenia NAME.")
		else:
			sg.popup_error("Błąd: Polecenie /NAME wymaga podania argumentu.")
			# print("Błąd: Polecenie /NAME wymaga podania argumentu.")
	elif message.lower().startswith("/list"):
		new_message = prepare_message("LIST", "")
		try:
			server.sendall(new_message)
		except socket.error:
			sg.popup_error("Błąd: Niepowodzenie w realizacji polecenia LIST.")
	elif message.lower().startswith("/join"):
		new_message_payload = message.split()
		if len(new_message_payload) >= 2:
			new_message_payload = new_message_payload[1].strip()
			new_message = prepare_message("JOIN", new_message_payload)
			try:
				server.sendall(new_message)
			except socket.error:
				sg.popup_error("Błąd: Niepowodzenie w realizacji polecenia JOIN.")
		else:
			sg.popup_error("Błąd: Polecenie /JOIN wymaga podania argumentu.")
			# print("Błąd: Polecenie /JOIN wymaga podania argumentu.")
	elif message.lower().startswith("/leave"):
		new_message = prepare_message("LEAVE", "")
		try:
			server.sendall(new_message)
		except socket.error:
			sg.popup_error("Błąd: Niepowodzenie w realizacji polecenia LEAVE.")
	elif message.lower().startswith("/users"):
		new_message = prepare_message("USERS", "")
		try:
			server.sendall(new_message)
		except socket.error:
			sg.popup_error("Błąd: Niepowodzenie w realizacji polecenia USERS.")
	elif message.lower().startswith("/quit"):
		new_message = prepare_message("QUIT", "")
		try:
			server.sendall(new_message)
		except socket.error:
			pass
		server.shutdown(socket.SHUT_RDWR)
		server.close()
		server_plain.close()
		return True
	else: # Zwykła wiadomość
		if len(message) > 4000:
			sg.popup_error("Zbyt długa wiadomość! Limit wiadomości to 4000 znaków.")
			# print("Zbyt długa wiadomość! Limit wiadomości to 4000 znaków.")
		new_message = prepare_message("MESSAGE", message)
		try:
			server.sendall(new_message)
		except socket.error:
			print("Nie udało się przesłać wiadomości.", text_color= 'red')

def handle_incoming():
	"""Funkcja odpowiadająca za przyjmowanie wiadomości od serwera"""
	while True:
		try:
			protocol_version, message_type, message_payload = receive(server)
			"""Zarządzanie sposobem reakcji na wiadomości odebrane od serwera."""
			if message_type == "MESSAGE":
				print(message_payload)
			elif message_type == "INFO":
				print(message_payload, text_color= 'blue')
			elif message_type == "OK":
				if message_payload.startswith("11"):
					# Zaakceptowano zmianę pseudonimu. Klient jest informowany
					# o tym w czacie, w wiadomości typu INFO.
					pass
				elif message_payload.startswith("21"):
					# Dołączenie do pokoju zakończone sukcesem.
					print(f"Dołączono do pokoju {message_payload.split()[1]}", text_color= 'green')
				elif message_payload.startswith("22"):
					print("Opuszczono pokój.", text_color= 'green')
			elif message_type == "ERROR":
				if message_payload.startswith("11"):
					window.write_event_value('-ERROR-POPUP-', (threading.current_thread().name, "Ta nazwa jest już zajęta"))
					# print('Nazwa zajęta', text_color= 'red')
					pass
				elif message_payload.startswith("12"):
					window.write_event_value('-ERROR-POPUP-', (threading.current_thread().name, "Nazwa jest niedozwolona. Maksymalna długość nazwy to 32 znaki. Dozwolone znaki to litery, cyfry oraz -._"))
					# print('Nazwa za długa', text_color= 'red')
				elif message_payload.startswith("21"):
					window.write_event_value('-ERROR-POPUP-', (threading.current_thread().name, "Żeby wysłać wiadomość, musisz najpierw dołączyć do pokoju rozmów z użyciem przycisku JOIN."))
					# print("Żeby wysłać wiadomość, musisz najpierw dołączyć do pokoju rozmów używając polecenia /JOIN NAZWA-POKOJU", text_color= 'red')
				elif message_payload.startswith("22"):
					window.write_event_value('-ERROR-POPUP-', (threading.current_thread().name, "Możesz znajdować się tylko w jednym pokoju naraz."))
					# print("Możesz znajdować się tylko w jednym pokoju naraz.", text_color= 'red')
				elif message_payload.startswith("23"):
					print("Serwer otrzymał nieprawidłowy typ wiadomości.", text_color= 'red')
				elif message_payload.startswith("24"):
					window.write_event_value('-ERROR-POPUP-', (threading.current_thread().name, "Nie jesteś członkiem żadnego pokoju."))
				elif message_payload.startswith("25"):
					window.write_event_value('-ERROR-POPUP-', (threading.current_thread().name, "Niedozwolona nazwa pokoju."))
			elif message_type == "LIST":
				if message_payload == "":
					print("Lista pokojów jest pusta.", text_color= 'blue')
				else:
					print("Lista pokojów:", text_color= 'blue')
					print(message_payload, text_color= 'navy blue')
			elif message_type == "USERS":
				window.write_event_value('-THREAD-', (threading.current_thread().name, message_payload))

		except (RuntimeError, ConnectionError) as e:
			window.write_event_value('-KILLME-', (threading.current_thread().name, e))
			server.close()
			server_plain.close()
			break

if __name__ != "__main__":
	exit(1)

sg.theme('GreenTan')

frame_layout = [[sg.Listbox(size=(32, 18), key='-ML2-', values=[], font=('Helvetica 10'))]]

layout = [[sg.Button('JOIN', button_color=(sg.YELLOWS[0], sg.BLUES[0]), size=(8,1)),
		   sg.Button('LIST', button_color=(sg.YELLOWS[0], sg.BLUES[0]), size=(8,1)),
		   sg.Button('NAME', button_color=(sg.YELLOWS[0], sg.BLUES[0]), size=(8,1)),
		   sg.Button('LEAVE', button_color=(sg.YELLOWS[0], sg.BLUES[0]), size=(8,1))],
          [sg.Multiline(size=(70, 20), key='-ML1-' + sg.WRITE_ONLY_KEY, disabled=True, font=('Helvetica 10')),
		   sg.Frame('Użytkownicy:', frame_layout, font='Helvetica 12', title_color='black')],
          [sg.Multiline(size=(70, 5), enter_submits=True, key='-QUERY-', do_not_clear=False),
           sg.Button('SEND', button_color=(sg.YELLOWS[0], sg.BLUES[0]), size=(14, 4), bind_return_key=True),
           sg.Button('EXIT', button_color=(sg.YELLOWS[0], sg.GREENS[0]), size=(14, 4))]]

window = sg.Window('Simple Messenger', layout, font=('Helvetica', ' 10'), default_button_element_size=(8,2), use_default_focus=False)

try:
	server_plain = socket.create_connection((server_address, server_port))
	server = ssl.wrap_socket(server_plain, cert_reqs=ssl.CERT_REQUIRED, ssl_version=ssl.PROTOCOL_TLSv1_2, ca_certs="pascert_trusted.crt")
except socket.error as e:
	print("Błąd przy tworzeniu gniazda SSL.")
	exit(1)

# Sprawdzanie certyfikatu serwera
cert = server.getpeercert()
if not cert or ssl.match_hostname(cert, "pkorba-simple-messenger"):
	print("Błąd: Nieprawidłowy certyfikat SSL.")
	exit(1)

# Wysłanie nicku klienta. W przypadku podania nicku zajętego / niepoprawnego.
# Klient proszony jest o ponowne podanie nazwy do momentu aż poda poprawny lub wciśnie przycisk cancel.
valid = False;
loginMessage = "Podaj nazwę użytkownika:"
while not valid:
	username = sg.popup_get_text(loginMessage)
	# Sprawdzenie czy klient wcisnął przycisk cancel.
	# Jeśli tak program jest zamykany.
	if username == None:
		server.shutdown(socket.SHUT_RDWR)
		server.close()
		server_plain.close()
		quit()
	message = prepare_message("NAME", username)
	server.sendall(message)
	protocol_version, message_type, message_payload = receive(server)
	if message_type != "ERROR":
		valid = True
	elif message_payload.startswith("12"):
		loginMessage = "Nazwa jest niedozwolona. Maksymalna długość nazwy to 32 znaki. Dozwolone znaki to litery, cyfry oraz -._\nPodaj nazwę użytkownika:"
	elif message_payload.startswith("11"):
		loginMessage = "Nazwa jest już zajęta.\nPodaj nazwę użytkownika:"

thread_incoming = threading.Thread(target=handle_incoming, args=[], daemon=True)
thread_incoming.start()
event = ''
# Pętla wysyłania wiadomości do serwera.
text_quit = False
while True and not text_quit:
	try:
		event, value = window.Read()
		print = lambda *args, **kwargs: window['-ML1-' + sg.WRITE_ONLY_KEY].print(*args, **kwargs)
		if event in (sg.WINDOW_CLOSE_ATTEMPTED_EVENT, 'EXIT') and sg.popup_yes_no('Czy na pewno chcesz wyjść?') == 'Yes':
			handle_input(server, server_plain, '/quit')
			window.close()
			break
		elif event == sg.WIN_CLOSED:
			break
		elif event == 'SEND':
			message = value['-QUERY-'].rstrip()
			if not message == "":
				text_quit = handle_input(server, server_plain, message)
		elif event == 'LIST':
			handle_input(server, server_plain, "/list")
		elif event == 'LEAVE':
			window.Element('-ML2-').Update(values=[])
			handle_input(server, server_plain, "/leave")
		elif event == 'JOIN':
			room = sg.popup_get_text("Podaj nazwę pokoju, do którego chcesz dołączyć:")
			if room != None:
				handle_input(server, server_plain, "/join " + room)
		elif event == 'NAME':
			name = sg.popup_get_text("Podaj nową nazwę użytkownika:")
			if name != None:
				handle_input(server,server_plain, "/name " + name)
		elif event == "-THREAD-":
			user_list = value["-THREAD-"][1]
			window.Element('-ML2-').Update(values=user_list.split("\n"))
		elif event == "-KILLME-":
			error = value["-KILLME-"][1]
			sg.popup_error(f"Zakończono połączenie z serwerem.\n{error}")
			window.close()
		elif event == "-ERROR-POPUP-":
			error = value["-ERROR-POPUP-"][1]
			sg.popup_ok(error)
		event = ''
	except (RuntimeError, ConnectionError) as e:
		sg.popup_error(f"Zerwano połączenie z serwerem\n{e}")
		server.close()
		server_plain.close()
		window.close()
		break
