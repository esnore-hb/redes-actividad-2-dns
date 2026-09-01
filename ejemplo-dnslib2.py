# --- Código de ejemplo dnslib:

import socket

import dnslib
from dnslib import DNSRecord
from dnslib.dns import CLASS, QTYPE


def send_dns_message(query_name, address, port):
	# Acá ya no tenemos que crear el encabezado porque dnslib lo hace por nosotros, por default pregunta por el tipo A
	qname = query_name
	q = DNSRecord.question(qname)
	server_address = (address, port)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		# lo enviamos, hacemos cast a bytes de lo que resulte de la función pack() sobre el mensaje
		sock.sendto(bytes(q.pack()), server_address)
		# En data quedará la respuesta a nuestra consulta
		data, _ = sock.recvfrom(4096)
		# le pedimos a dnslib que haga el trabajo de parsing por nosotros
		d = DNSRecord.parse(data)
	finally:
		sock.close()
	# Ojo que los datos de la respuesta van en en una estructura de datos
	return d

def print_dns_reply_elements(dnslib_reply):
	# header section
	print(">>--------------- HEADER SECTION ---------------<<\n")
	print(f"----------- dnslib_reply.header -----------\n{dnslib_reply.header}\n")

	qr_flag = dnslib_reply.header.get_qr()
	print(f"-> qr_flag = {qr_flag}")

	number_of_query_elements = dnslib_reply.header.q
	print(f"-> number_of_query_elements = {number_of_query_elements}")

	number_of_answer_elements = dnslib_reply.header.a
	print(f"-> number_of_answer_elements = {number_of_answer_elements}")

	number_of_authority_elements = dnslib_reply.header.auth
	print(f"-> number_of_authority_elements = {number_of_authority_elements}")

	number_of_additional_elements = dnslib_reply.header.ar
	print(f"-> number_of_additional_elements = {number_of_additional_elements}")
	print(">>----------------------------------------------<<\n")

	print(">>---------------- QUERY SECTION ---------------<<\n")
	# query section
	all_querys = dnslib_reply.questions  # lista de objetos tipo dnslib.dns.DNSQuestion
	print(f"-> all_querys = {all_querys}")

	first_query = dnslib_reply.get_q()  # primer objeto en la lista all_querys
	print(f"-> first_query = {first_query}")

	domain_name_in_query = first_query.get_qname()  # nombre de dominio por el cual preguntamos
	print(f"-> domain_name_in_query = {domain_name_in_query}")

	query_class = CLASS.get(first_query.qclass)
	print(f"-> query_class = {query_class}")

	query_type = QTYPE.get(first_query.qtype)
	print(f"-> query_type = {query_type}")

	print(">>----------------------------------------------<<\n")

	print(">>---------------- ANSWER SECTION --------------<<\n")
	# answer section
	if number_of_answer_elements > 0:
		all_resource_records = dnslib_reply.rr  # lista de objetos tipo dnslib.dns.RR
		print(f"-> all_resource_records = {all_resource_records}")

		first_answer = dnslib_reply.get_a()  # primer objeto en la lista all_resource_records
		print(f"-> first_answer = {first_answer}")

		domain_name_in_answer = first_answer.get_rname()  # nombre de dominio por el cual se está respondiendo
		print(f"-> domain_name_in_answer = {domain_name_in_answer}")

		answer_class = CLASS.get(first_answer.rclass)
		print(f"-> answer_class = {answer_class}")

		answer_type = QTYPE.get(first_answer.rtype)
		print(f"-> answer_type = {answer_type}")

		answer_rdata = first_answer.rdata  # rdata asociada a la respuesta
		print(f"-> answer_rdata = {answer_rdata}")
	else:
		print(f"-> number_of_answer_elements = {number_of_answer_elements}")

	print(">>----------------------------------------------<<\n")

	print(">>-------------- AUTHORITY SECTION -------------<<\n")
	# authority section
	if number_of_authority_elements > 0:
		authority_section_list = dnslib_reply.auth  # contiene un total de number_of_authority_elements
		print(f"-> authority_section_list = {authority_section_list}")

		if len(authority_section_list) > 0:
			authority_section_RR_0 = authority_section_list[0]  # objeto tipo dnslib.dns.RR
			print(f"-> authority_section_RR_0 = {authority_section_RR_0}")

			auth_type = QTYPE.get(authority_section_RR_0.rtype)
			print(f"-> auth_type = {auth_type}")

			auth_class = CLASS.get(authority_section_RR_0.rclass)
			print(f"-> auth_class = {auth_class}")

			auth_time_to_live = authority_section_RR_0.ttl
			print(f"-> auth_time_to_live = {auth_time_to_live}")

			authority_section_0_rdata = authority_section_RR_0.rdata
			print(f"-> authority_section_0_rdata = {authority_section_0_rdata}")

			# si recibimos auth_type = 'SOA' este es un objeto tipo dnslib.dns.SOA
			if isinstance(authority_section_0_rdata, dnslib.dns.SOA):
				primary_name_server = authority_section_0_rdata.get_mname()  # servidor de nombre primario
				print(f"-> primary_name_server = {primary_name_server}")

			elif isinstance(authority_section_0_rdata, dnslib.dns.NS): # si en vez de SOA recibimos un registro tipo NS
				name_server_domain = authority_section_0_rdata  # entonces authority_section_0_rdata contiene el nombre de dominio del primer servidor de nombre de la lista
				print(f"-> name_server_domain = {name_server_domain}")
	else:
		print(f"-> number_of_authority_elements = {number_of_authority_elements}")
	print(">>----------------------------------------------<<\n")

	print(">>------------- ADDITIONAL SECTION -------------<<\n")
	if number_of_additional_elements > 0:
		additional_records = dnslib_reply.ar  # lista que contiene un total de number_of_additional_elements DNS records
		print(f"-> additional_records = {additional_records}")

		first_additional_record = additional_records[0]  # objeto tipo dnslib.dns.RR
		print(f"-> first_additional_record = {first_additional_record}")

		# En caso de tener additional records, estos pueden contener la IP asociada a elementos del authority section
		ar_class = CLASS.get(first_additional_record.rclass)
		print(f"-> ar_class = {ar_class}")

		ar_type = QTYPE.get(first_additional_record.rclass)  # para saber si esto es asi debemos revisar el tipo de record
		print(f"-> ar_type = {ar_type}")

		if ar_type == 'A': # si el tipo es 'A' (Address)
			first_additional_record_rname = first_additional_record.rname  # nombre de dominio
			print(f"-> first_additional_record_rname = {first_additional_record_rname}")

			first_additional_record_rdata = first_additional_record.rdata  # IP asociada
			print(f"-> first_additional_record_rdata = {first_additional_record_rdata}")
	else:
		print(f"-> number_of_additional_elements = {number_of_additional_elements}")
	print(">>----------------------------------------------<<\n")

# Vamos a preguntar por cl. a un resolver existente
dnslib_reply_1 = send_dns_message("cl.", "8.8.8.8", 53)
# Como cl se encarga de un area entera, vamos a recibir un registro SOA que nos indica el primary_name_server = a.nic.cl.
print_dns_reply_elements(dnslib_reply_1)

print(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
# Si ahora queremos saber la IP, podemos volver a preguntarle al resolver. Esta vez preguntamos por el primary_name_server
dnslib_reply_2 = send_dns_message("a.nic.cl.", "8.8.8.8", 53)
# En las respuestas vamos a obtener la IP de este primary_name_server
print_dns_reply_elements(dnslib_reply_2)

# Propuesto: Utilizando la IP que puede ver en pantalla, ahora consulte por uchile.cl, pero consultele al NS de cl.
# compare esta respuesta con la respuesta obteniida al preguntar por uchile.cl al resolver "8.8.8.8".
# ¿Qué diferencias observa?


"""
# --- Añadir answer a dnslib
from dnslib.dns import RR, A
from dnslib import DNSRecord, DNSHeader, DNSQuestion

# Modificar el mensaje de pregunta (opción 1)
dns_query.add_answer(RR(qname, QTYPE.A, rdata=A(ip_answer)))

# Modificar el mensaje de pregunta (opción 2)
dns_query.add_answer(*RR.fromZone("{} A {}".format(qname, ip_answer)))

# Crear un nuevo mensaje que contenga la pregunta y la respuesta
"""