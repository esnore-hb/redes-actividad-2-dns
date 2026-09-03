import socket

from dnslib import DNSRecord, QTYPE

# IP_VM = "13.8.0.5"
#IP_VM = "127.0.0.53"
IP_VM= "127.0.0.1"
DNS = "1.1.1.1"
ROOT_IP = "198.41.0.4"
# DNS = "1.0.0.1"
# DNS = "8.8.8.8"
# DNS = "8.8.4.4"
port = 8000
server_address = (IP_VM, port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(server_address)
print("esperando...")


# funcion para enviar mensaje DNS a servidor DNS y recibir respuesta
def consultar(mensaje_consulta: bytes, ip_addr: str) -> bytes:
	dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		dns_socket.settimeout(3)
		dns_socket.sendto(mensaje_consulta, (ip_addr, 53))
		data, _ = dns_socket.recvfrom(4096)
		return data
	except socket.timeout:
		return b""
	finally:
		dns_socket.close()


# funcion que resuelve el dominio siguiendo la jerarquia desde la raiz
def resolver(mensaje_consulta: bytes, ip_addr=ROOT_IP) -> bytes:

	print("(debug) consultando a", ip_addr)  # Debug

	# a) enviamos la consulta al name server de turno
	respuesta = consultar(mensaje_consulta, ip_addr)
	if not respuesta:
		return b""  # timeout

	d = DNSRecord.parse(respuesta)

	# b) si hay algun registro tipo A en Answer, terminamos
	answer_A = [rr for rr in d.rr if rr.rtype == QTYPE.A]
	if answer_A:
		return respuesta  # bytes crudos, para responderle a dig

	# c) si hay registros NS en Authority, nos estan delegando
	ns_records = [rr for rr in d.auth if rr.rtype == QTYPE.NS]
	if not ns_records:
		# d) cualquier otra cosa (CNAME, SOA, vacio) se ignora
		return b""

	# c.i) si el glue viene en Additional, saltamos a esa IP
	glue = [rr for rr in d.ar if rr.rtype == QTYPE.A]
	if glue:
		return resolver(mensaje_consulta, str(glue[0].rdata))

	# c.ii) sin glue: resolvemos primero la IP del name server
	nombre_ns = str(ns_records[0].rdata)
	print("(debug) sin glue, resolviendo IP de", nombre_ns)  # Debug
	sub_respuesta = resolver(DNSRecord.question(nombre_ns).pack())
	if not sub_respuesta:
		return b""
	sub = DNSRecord.parse(sub_respuesta)
	ips_ns = [rr for rr in sub.rr if rr.rtype == QTYPE.A]
	if not ips_ns:
		return b""
	return resolver(mensaje_consulta, str(ips_ns[0].rdata))


# recibir consulta del cliente, resolverla y responder
while True:

	data, addr = sock.recvfrom(4096)
	respuesta = resolver(data)
	if respuesta:
		sock.sendto(respuesta, addr)
