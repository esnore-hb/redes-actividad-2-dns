import socket
from collections import Counter, deque

from dnslib import DNSRecord, QTYPE

IP_VM = "127.0.0.53"
ROOT_IP = "1.0.0.1"
port = 8000
server_address = (IP_VM, port)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(server_address)
DEBUG = True

TOP_N = 3
HISTORIAL_MAXLEN = 20
historial_consultas: deque[str] = deque(maxlen=HISTORIAL_MAXLEN)
respuestas_guardadas: dict[str, bytes] = {}


def dominios_mas_repetidos() -> set[str]:
	conteo = Counter(historial_consultas)
	return {dominio for dominio, _ in conteo.most_common(TOP_N)}


def debug_print(msg: str) -> None:
	if DEBUG:
		print(f"[DEBUG] {msg}")


def resolver(mensaje_consulta: bytes, ip_addr=ROOT_IP, ns_nombre=".") -> bytes:
	nombre_dominio = str(DNSRecord.parse(mensaje_consulta).q.qname)

	debug_print(
		f"Consultando '{nombre_dominio}' a '{ns_nombre}' con dirección IP '{ip_addr}'"
	)

	dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		dns_socket.settimeout(3)
		dns_socket.sendto(mensaje_consulta, (ip_addr, 53))
		data, _ = dns_socket.recvfrom(4096)
		return data
	except socket.timeout:
		return b""
	dns_socket.close()

	d: DNSRecord = DNSRecord.parse(data)
	for rr in d.rr:
		if QTYPE[rr.rtype] == "A":
			debug_print(f"Respuesta obtenida desde {ip_addr}: {nombre_dominio} -> {str(rr.rdata)}")
			return data

	ns_names = [str(auth.rname) for auth in d.auth if QTYPE[auth.rtype] == "NS"]
	if ns_names:
		ns_targets = [str(auth.rdata) for auth in d.auth if QTYPE[auth.rtype] == "NS"]
		siguiente_ns_nombre = ns_targets[0] if ns_targets else ns_names[0]

		additional_ips = [str(ar.rdata) for ar in d.ar if QTYPE[ar.rtype] == "A"]
		if additional_ips:
			return resolver(mensaje_consulta, additional_ips[0], siguiente_ns_nombre)
		else:
			ns_domain = str(siguiente_ns_nombre)  # nombre del NS a resolver
			ns_query = DNSRecord.question(ns_domain).pack()

			debug_print(f"No hay IP adicional para '{siguiente_ns_nombre}', resolviendo su IP primero")
			ns_response = resolver(ns_query, ROOT_IP, ".")
			if not ns_response:
				return b""

			ns_record = DNSRecord.parse(ns_response)
			ns_ip = None
			for rr in ns_record.rr:
				if QTYPE[rr.rtype] == "A":
					ns_ip = str(rr.rdata)
					break

			if ns_ip is None:
				return b""

			return resolver(mensaje_consulta, ns_ip, ns_domain)

	return b""


def resolver_con_cache(mensaje_consulta: bytes) -> bytes:
	nombre_dominio = str(DNSRecord.parse(mensaje_consulta).q.qname)

	top_dominios = dominios_mas_repetidos()

	if nombre_dominio in top_dominios and nombre_dominio in respuestas_guardadas:
		debug_print(f"Usando CACHÉ para '{nombre_dominio}' (top {TOP_N} más consultados)")
		respuesta = respuestas_guardadas[nombre_dominio]
		nueva_respuesta = DNSRecord.parse(respuesta)
		nueva_respuesta.header.id = DNSRecord.parse(mensaje_consulta).header.id
		respuesta = nueva_respuesta.pack()
	else:
		debug_print(f"'{nombre_dominio}' no está en caché, resolviendo desde cero")
		respuesta = resolver(mensaje_consulta)
		if respuesta:
			respuestas_guardadas[nombre_dominio] = respuesta

	historial_consultas.append(nombre_dominio)

	return respuesta


while True:

	data, addr = sock.recvfrom(4096)
	ans = resolver_con_cache(data)
	if ans:
		sock.sendto(ans, addr)

""" --- Experimentos
[DEBUG] 'www.webofscience.com.' no está en caché, resolviendo desde cero
[DEBUG] Consultando 'www.webofscience.com.' a '.' con dirección IP '198.41.0.4'
[DEBUG] Consultando 'www.webofscience.com.' a 'l.gtld-servers.net.' con dirección IP '192.41.162.30'
[DEBUG] Consultando 'www.webofscience.com.' a 'ns-342.awsdns-42.com.' con dirección IP '205.251.193.86'
[DEBUG] No hay IP adicional para 'ns-1010.awsdns-62.net.', resolviendo su IP primero
[DEBUG] Consultando 'ns-1010.awsdns-62.net.' a '.' con dirección IP '198.41.0.4'
[DEBUG] Consultando 'ns-1010.awsdns-62.net.' a 'm.gtld-servers.net.' con dirección IP '192.55.83.30'
[DEBUG] Consultando 'ns-1010.awsdns-62.net.' a 'g-ns-192.awsdns-62.net.' con dirección IP '205.251.192.192'
[DEBUG] Respuesta obtenida desde 205.251.192.192: ns-1010.awsdns-62.net. -> 205.251.195.242
[DEBUG] Consultando 'www.webofscience.com.' a 'ns-1010.awsdns-62.net.' con dirección IP '205.251.195.242'
[DEBUG] No hay IP adicional para 'ns-1010.awsdns-62.net.', resolviendo su IP primero

`dig -p8000 @127.0.0.53 www.webofscience.com`
El programa falla al caer en un ciclo eterno, dado que siempre toma la primera respuesta que encuentra.

`dig -p8000 @127.0.0.53 www.cc4303.bachmann.cl`
Lo mismo sucede

Realice varias consultas a un mismo dominio y a través del modo debug vea a qué Name Servers y direcciones IP le pregunta su resolver en cada consulta. ¿Son siempre los mismos Name Servers? ¿Por qué cree usted que sucede esto? Anote las respuestas a estas preguntas en su informe.
Esto porque el DNS quiere aligerar su pega, y te dirige al que menos este ocupado,
o que esté mas cerca tuyo. Se basa en el fundamento de ser redundante.
"""
