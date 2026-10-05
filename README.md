# ESP-NOW seguro: ECDH autenticado + AES-GCM

Proyecto C++ para dos NodeMCU-32S, Arduino y PlatformIO. Mantiene ESP-NOW del
proyecto original; completa el protocolo y sus pruebas. No utiliza servidor
PC, IP, WiFiManager ni RSA. La rubrica permite ECDH, y el alumno confirmo
mantener esta alternativa.

## Prueba rapida con tu companero

1. Abrir ESTA carpeta Project en VS Code con PlatformIO.
2. Compartir de forma privada el mismo proyecto con el companero, incluyendo
   include/pair_secret.h. Ambos deben usar la misma credencial.
3. Tu placa: Project Tasks > esp_a > General > Upload.
   Su placa: Project Tasks > esp_b > General > Upload.
4. Abrir los dos monitores a 115200, terminacion LF. Cada placa usa su propia
   computadora. El USB solo proporciona energia y consola; el texto viaja por
   ESP-NOW en canal 1, sin router.
5. Escribir connect SOLO en A. B responde automaticamente.
6. Esperar [SESSION OK] en AMBOS monitores. Escribir texto en cualquier lado.
   El receptor muestra [SUCCESS] Verificado y descifrado.
   El emisor muestra [CONFIRMADO] y RTT_TEXT al verificar el ACK cifrado.
   Esperar esa confirmacion (o timeout) antes del siguiente texto.

No cargar esp_a en las dos placas. El protocolo v2 no es compatible con el
firmware original sin autenticar; ambas placas requieren esta version.
El limite de texto es 128 bytes UTF-8 (no necesariamente 128 caracteres).

## Comandos

| Comando | Funcion |
|---|---|
| connect | A inicia ECDH; B responde automaticamente. |
| /help | Mostrar instrucciones. |
| /reset | Borrar sesion; hacerlo en ambas placas antes de otro connect. |
| /demo on /demo off | Mostrar/ocultar publicas, ciphertext y tag. Nunca imprime claves secretas. |
| /ping | Ping/pong cifrado, RTT en microsegundos. |
| /stats | TX, RX, rechazos, memoria y descartes de la cola. |
| /metricas | Repetir la guia de columnas y unidades de las medidas. |
| /attack ciphertext texto | Alterar un bit del ciphertext. |
| /attack tag texto | Alterar un bit del tag. |
| /attack forged texto | Inyectar ciphertext y tag aleatorios con metadatos plausibles. |
| /attack replay | Reenviar exactamente el ultimo texto normal enviado. |
| /attack sender texto | Alterar MAC declarada. |
| /attack sid texto | Alterar SID. |
| /attack seq texto | Alterar SEQ y el nonce correspondiente. |

Los ataques se rechazan sin entregar texto ni actualizar la ventana replay.
Un texto rechazado no genera ACK. Los ACK alterados o repetidos tampoco
confirman el texto ni generan otra muestra RTT_TEXT.
La sesion permanece utilizable; enviar texto normal despues de cada ataque.
Es un experimento controlado desde el propio firmware, no un sniffer de terceros.

## Autenticacion

La credencial privada aleatoria de 32 bytes autoriza esta pareja. Se provisiona
por USB y nunca se transmite. HMAC-SHA256 autentica HELLO y el intercambio
completo. ECDH genera un secreto nuevo; HKDF deriva claves AES por direccion.
READY confirma posesion de las claves antes de aceptar textos.

No hay clave AES fija ni fallback. Tener una MAC no basta para autenticar.
La autorizacion se basa en poseer la credencial de la pareja; copiar esa
credencial permite clonar un participante. No es una identidad certificada
individual ni un sistema auditado para produccion.

## Pruebas y entregables

- docs/PRUEBAS.md: guion completo con dos placas y con intruso.
- docs/PROTOCOLO.md: bytes, estados y decisiones de seguridad.
- docs/EXPLICACION.md: explicacion para estudiar y defender el proyecto.
- docs/RUBRICA.md: requisitos y evidencia pendiente.
- docs/architecture.md / architecture.png: arquitectura actual.
- docs/protocol.md / protocol.png: secuencia actual.
- output/pdf/INFORME.pdf: informe tecnico y medidas de PC.
- measurements/pruebas.txt: suite automatizada del codigo compartido.
- measurements/pc.csv: medidas PC reales, SIN radio.

Las pruebas de PC y la compilacion no sustituyen las dos placas. Completar
las evidencias fisicas y las medidas ESP32 antes de entregar el informe.

## Clave y compilacion

include/pair_secret.h es privado y se excluye de Git. No regenerarlo en cada
computadora: ambas placas requieren el MISMO archivo. Para una pareja nueva:
build/generar_credencial.exe desde esta carpeta crea el archivo si no existe.
Una credencial nueva exige recompilar/cargar ambas placas.

PlatformIO fija espressif32@6.12.0 / Arduino 2.0.17 para reproducibilidad.
hkdf_compat.c procede del HKDF oficial de mbedTLS que Arduino no enlaza.
Las bibliotecas criptograficas contienen C; la aplicacion propia es C++.

Pruebas PC en Windows: build/pruebas.exe y
build/mediciones.exe measurements/pc.csv. Para recompilar con MinGW:
compilar.ps1. Los fuentes mbedTLS 2.28.10 se incluyen en vendor/mbedtls
(licencia incluida); PlatformIO usa el mbedTLS integrado en Arduino.

## Medidas

METRIC,direccion,plaintext_bytes,packet_bytes,encrypt_us,verify_decrypt_us,rtt_us

Al arrancar aparece una guia en espanol. /metricas la repite sin reiniciar.
Con /demo on, cada linea METRIC tiene una explicacion con nombres y unidades.
Ejemplo ilustrativo: METRIC,TX,5,66,658,0,0 significa envio, texto de 5 bytes,
paquete de 66 bytes y 658 us (0.658 ms) de cifrado/preparacion. Los otros dos
tiempos no aplican a TX; la explicacion los muestra como N/A.
TX no confirma recepcion: comprobar [SUCCESS] en la otra placa.
/demo off conserva el CSV y oculta las explicaciones para medir rendimiento.

TX incluye AES-GCM y serializacion. RX incluye parseo, origen, SID, nonce,
GCM y ventana replay. packet_bytes es el datagrama de aplicacion, sin cabeceras
802.11/ESP-NOW. Los ceros de columnas no aplicables no son tiempos medidos.
HANDSHAKE_MS mide el establecimiento completo, incluidos espera y reintentos.
Para rendimiento usar /demo off y separar ping de los textos.

Cada TEXT normal recibe un ACK AES-GCM con su SEQ original en 4 bytes
big-endian. El ACK ocupa 65 bytes, tiene su propio SEQ/nonce y control replay.
RTT_TEXT comienza antes de cifrar TEXT y termina despues de verificar el ACK,
antes de imprimirlo. Incluye criptografia en ambos extremos, colas y radio.
RX mide la verificacion/descifrado del texto sin incluir preparar el ACK.
TX mide cifrado/preparacion, no el recorrido. RTT_TEXT es ida/vuelta;
no mide un trayecto ni comprueba que una persona haya leido el mensaje.
Si falta el ACK en 5 s, hay TIMEOUT sin valor RTT inventado; el texto pudo
haber llegado y perderse el ACK. No hay retransmision automatica de TEXT.
Las dos placas necesitan esta actualizacion para producir los ACK de TEXT.
resumir_metricas.ps1 genera *_rtt_texto.csv con medias/minimos/maximos por
tamaño y numero de textos confirmados; *_rtt.csv sigue correspondiendo a /ping.
TX/RX corresponden solo a TEXT. PING_TX/RX, PONG_TX/RX y ACK_TX/RX quedan
separados para no mezclar sus tiempos con los textos, incluso si tienen 8 bytes.

## Wireshark

ESP-NOW no usa TCP/IP: tcp.port == 8765 no captura este proyecto. Una captura
del aire requiere un adaptador compatible con modo monitor y canal 1.
El monitor serial muestra una copia hexadecimal de los bytes de aplicacion.
Para replay, /attack replay reutiliza el datagrama realmente generado y guardado.
