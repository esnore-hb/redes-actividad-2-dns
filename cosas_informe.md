# Cosas para el informe

## Paso 2 - ¿Qué tipo de socket corresponde y por qué?

Socket **UDP** (`socket.SOCK_DGRAM`), no orientado a conexión. La razón es el costo:
el overhead de TCP no se justifica para el tamaño del intercambio.

Una consulta DNS típica son ~30 bytes de query y ~100 bytes de respuesta: un solo
ida y vuelta. Con TCP habría que pagar antes:

- **Handshake de 3 vías** (SYN, SYN-ACK, ACK): un RTT completo *antes* de mandar el
  primer byte de la consulta, o sea se duplica la latencia de algo que en UDP toma 1 RTT.
- **Cierre de conexión** (FIN/ACK): otro intercambio después.
- **Estado en el servidor**: un servidor raíz atiende millones de consultas por segundo;
  mantener tabla de conexiones, buffers y timers por cada una es carísimo en memoria y
  lo deja expuesto a ataques de agotamiento de conexiones.

Son ~5 paquetes de overhead para transportar 1 paquete útil.

**Precisión importante:** UDP *no* reintenta por sí solo. No tiene retransmisión, ni
ACKs, ni garantía de orden. Si se pierde el datagrama nadie se entera. Quien reintenta
es el **resolver, en la capa de aplicación**: pone un timeout y si no llega respuesta
reenvía la query o le pregunta a otro name server. Como la consulta cabe en un solo
paquete, reintentar es trivial: se manda el mismo datagrama de nuevo. No hay nada que
reordenar ni flujo que reconstruir, así que la confiabilidad que daría TCP no se necesita.

**DNS sí usa TCP en dos casos:** cuando la respuesta no cabe en UDP (el servidor marca
el flag TC de *truncated* y el cliente reintenta por TCP) y en transferencias de zona
(AXFR), donde sí hay muchos datos y el trade-off se invierte.

## Paso 2 - Mensaje DNS crudo recibido

Salida del resolver al ejecutar `dig -p8000 @127.0.0.1 example.com`:

```
Received 52 bytes from ('127.0.0.1', 51475)
Data: b"D'\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00)\x04\xd0\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\x1cb\xce\xc1Tz\xd7L"
```

### Observación: el mensaje llega 3 veces

No es un bug, es `dig` **reintentando** porque el resolver todavía no responde. Confirma
en la práctica lo dicho arriba sobre UDP: el protocolo no retransmite solo, quien
reintenta es la aplicación. El puerto de origen cambia en cada intento
(51475, 37187, 33051) pero el mensaje es idéntico.

Del lado de dig se ve:

```
;; communications error to 127.0.0.1#8000: timed out   (x3)
;; no servers could be reached
```

### Desglose byte a byte del mensaje

| Bytes | Campo | Valor |
|---|---|---|
| `D'` | ID de la consulta | 2 bytes aleatorios |
| `\x01 ` | Flags | `0x0120`: es query, con recursión deseada (RD) |
| `\x00\x01` | QDCOUNT | 1 pregunta |
| `\x00\x00` | ANCOUNT | 0 |
| `\x00\x00` | NSCOUNT | 0 |
| `\x00\x01` | ARCOUNT | 1 |
| `\x07example\x03com\x00` | QNAME | ver abajo |
| `\x00\x01` | QTYPE | 1 = A |
| `\x00\x01` | QCLASS | 1 = IN |
| `\x00\x00)\x04\xd0...` | Registro OPT (EDNS) | lo agrega dig, por eso ARCOUNT=1 |

**Codificación del QNAME:** los nombres de dominio no van como texto plano con puntos.
Van como secuencia de *labels*, cada una precedida por un byte con su largo, y
terminadas por un byte `\x00`:

```
\x07 example  \x03 com  \x00
 (7)           (3)      (fin)
```

## Paso 3 - Parseo del mensaje DNS

Se optó por **dnslib** en vez de parseo manual con `binascii`. Con dnslib basta
`DNSRecord.parse(data)`: el objeto resultante **ya es** la estructura de datos manejable
que pide el enunciado, porque expone directamente todos los campos recomendados:

| Campo recomendado | Atributo dnslib |
|---|---|
| Qname | `d.get_q().get_qname()` |
| ANCOUNT | `d.header.a` |
| NSCOUNT | `d.header.auth` |
| ARCOUNT | `d.header.ar` |
| Answer | `d.rr` |
| Authority | `d.auth` |
| Additional | `d.ar` |

La nota del enunciado sobre "guardar la información en su estructura" apunta sobre todo
al camino de parseo manual, donde sí hay que construir esa estructura a mano.

### Salida obtenida

Parseando el mensaje que envía `dig -p8000 @127.0.0.1 example.com`:

```
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 33936
;; flags: rd ad; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; QUESTION SECTION:
;example.com.                   IN      A
;; ADDITIONAL SECTION:
;; OPT PSEUDOSECTION
; EDNS: version: 0, flags: ; udp: 1232
; EDNS: code: 10; data: cfd8e67d65ec32ec
```

Lectura de la salida:

- `opcode: QUERY` → es una pregunta, no una respuesta (flag QR en 0).
- `ANSWER: 0, AUTHORITY: 0` → secciones vacías, como corresponde a una pregunta.
- `flags: rd` → *recursion desired*: dig le pide al resolver que haga el trabajo completo
  de resolución. Es lo normal cuando un cliente le habla a un resolver.
- `ADDITIONAL: 1` con el OPT → pseudo-registro de EDNS que agrega dig; no es información
  DNS propiamente tal, anuncia que acepta respuestas UDP de hasta 1232 bytes.
- El `id: 33936` se repite en los tres mensajes recibidos: es el mismo mensaje
  reintentado, no tres consultas distintas.

**Limitación del test:** con una pregunta no se puede verificar la lectura de
Answer/Authority/Additional porque vienen vacías. Eso se valida recién al recibir
respuestas reales de los name servers en el paso 4.

## Paso 4 - Resolver iterativo

### Diseño: dos funciones separadas

El programa cumple **dos roles distintos** y por eso usa dos sockets:

| | Socket servidor (paso 2) | Socket cliente (paso 4) |
|---|---|---|
| Rol | servidor | cliente |
| Bindeado | sí, a `(IP_VM, 8000)` | no |
| Habla con | dig | los name servers |
| Vida | todo el programa | una consulta, luego se cierra |

- `consultar(mensaje, ip)`: mecánica pura. Abre socket UDP, manda al puerto 53 de esa IP,
  espera, cierra y retorna los **bytes crudos**. Con `settimeout(3)` y `try/except/finally`
  para no colgarse ni filtrar descriptores.
- `resolver(mensaje, ip_addr=ROOT_IP)`: la lógica de decisión. Llama a `consultar`, parsea
  y decide el siguiente salto.

Se implementó de forma **totalmente recursiva**. Hay dos tipos de llamada recursiva, que se
distinguen por el primer argumento:

- `resolver(mensaje_consulta, otra_ip)` → **misma** pregunta, siguiente escalón de la jerarquía.
- `resolver(DNSRecord.question(nombre_ns).pack())` → pregunta **distinta** (el nombre del NS),
  desde la raíz. Es el caso c.ii.

Alternativa considerada: un `while` que va reasignando `ip_addr` para los saltos y deja la
recursión solo para c.ii. Es equivalente y más robusto ante cadenas largas de delegación
(no arriesga `RecursionError`), pero la versión recursiva calza más literal con la firma
que pide el enunciado.

### Decisión clave: retornar bytes crudos

`resolver` retorna la respuesta **tal como llegó del name server**, sin re-empaquetar. Esto
importa porque:

- El mensaje conserva el ID de la consulta original de dig, así que dig la acepta.
- Re-armar con `.pack()` podría alterar detalles del mensaje.

Como efecto secundario, dig muestra `WARNING: recursion requested but not available`: dig pide
recursión (flag `rd`) pero la respuesta del servidor autoritativo no trae el flag `ra`. Es
inofensivo, pero es consecuencia directa de reenviar los bytes crudos en vez de construir una
respuesta propia.

### Detalle de implementación: filtrar Additional por tipo

En la sección Additional vienen registros **A, AAAA y OPT mezclados**. Tomar `d.ar[0]` a secas
puede entregar una dirección IPv6, y mandarle un datagrama IPv4 falla. Por eso el filtro es
siempre por tipo:

```python
glue = [rr for rr in d.ar if rr.rtype == QTYPE.A]
```

Lo mismo explica que el header diga `ADDITIONAL: 15` pero se vean 14 registros: el 15º es el
pseudo-registro OPT de EDNS.

### Primera delegación observada (respuesta de la raíz)

Consultando `www.uchile.cl` a `198.41.0.4`:

```
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 7, ADDITIONAL: 15
;; AUTHORITY SECTION:
cl.                     172800  IN      NS      cl2-tld.d-zone.ca.
cl.                     172800  IN      NS      a.nic.cl.
...
;; ADDITIONAL SECTION:
cl2-tld.d-zone.ca.      172800  IN      A       185.159.198.56
cl2-tld.d-zone.ca.      172800  IN      AAAA    2620:10a:80ab::56
a.nic.cl.               172800  IN      A       190.124.27.10
...
```

Lectura: `flags: qr` indica que ya es una respuesta. `ANSWER: 0` → la raíz no sabe la IP y no
pretende averiguarla; **entrega el siguiente paso, no la respuesta**. Esa es exactamente la
diferencia con un resolver recursivo como 1.1.1.1, que habría hecho todos los saltos y
devuelto la IP final.

### Test: dig -p8000 @127.0.0.1 www.uchile.cl

Traza del modo debug — tres saltos:

```
(debug) consultando a 198.41.0.4      <- raiz
(debug) consultando a 185.159.198.56  <- NS de cl.
(debug) consultando a 200.89.70.3     <- NS de uchile.cl
```

Respuesta de dig:

```
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
;; ANSWER SECTION:
www.uchile.cl.          300     IN      A       200.89.76.36
;; Query time: 168 msec
;; SERVER: 127.0.0.1#8000(127.0.0.1) (UDP)
```

Resuelve a **200.89.76.36**, que coincide con lo esperado por la pauta. El flag `aa`
(*authoritative answer*) confirma que la respuesta viene del servidor que manda en la zona
`uchile.cl`, no de una caché intermedia.
