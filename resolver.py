import socket

# IP_VM = "13.8.0.5"
IP_VM = "127.0.0.1"
port = 8000
server_address = (IP_VM, port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def resolver(mensaje_consulta: bytes, ip_addr=str) -> bytes:
	pass
