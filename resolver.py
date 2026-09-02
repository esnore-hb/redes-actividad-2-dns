import socket

from dnslib import DNSRecord

# IP_VM = "13.8.0.5"
IP_VM = "127.0.0.53"
DNS = "1.1.1.1"
# DNS = "1.0.0.1"
# DNS = "8.8.8.8"
# DNS = "8.8.4.4"

port = 8000
server_address = (IP_VM, port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(server_address)

def resolver(mensaje_consulta: bytes, ip_addr=str) -> bytes:
	# redirigir mensaje y recivir respuesta DNS
	dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	dns_socket.sendto(mensaje_consulta, (DNS, 53))
	data, addr = dns_socket.recvfrom(4096)

	d: DNSRecord = DNSRecord.parse(data)
	print(d) # Debug


while True:

	data, addr = sock.recvfrom(4096)
	ans = resolver(data, addr)
