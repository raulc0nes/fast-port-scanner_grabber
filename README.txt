??? para compilar: gcc -o grabber grabber.c -pthread ???
e8c595df0f2f4a177c6894503a0988cead3c2e3a61270c566162085a52dd7a0d  grabber
2fe29a974f90c71e911d3fe2cac6a0d98175818ded740dd4eec2aabdb30f3b73  grabber.c
95858d22f672c385476f1b750b837f36cfda6050ff9caf549e7b30626291eb95  grabber.zip

## escáner con resolución de nombres
## el escaneo procede con las 4 técnicas en threads diferentes
## ( 1 - SYN ) : la más rápida, manda paquete syn y espera syn-ack
## ( 2 - TCP Connect ) : conex. tcp completa, 3 vías de handshake
## ( 3 - UDP ) : envía udp y espera icmp "inalcanzable"
## ( 4 - FIN ) : tcp "flagueado" con fin, recibe rst si puerto cerrado
## el tiempo de espera (timeout) se ajusta dinámicamente en función del tiempo de respuesta promedio
## estructura en 'pseudo_header' definida con la función checksum para calcular los chksum tcp

tuusuario@tumaquina:~# ./grabber 
Uso: ./grabber <IP objetivo> [comunes/todos]
tuusuario@tumaquina:~# ./grabber localhost todos
IP resuelta: 127.0.0.1
Progreso: [459/65535] (0%)
Progreso: [12359/65535] (18%)o banner
Puerto 12345 abierto. Banner: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3
Progreso: [65535/65535] (100%)
Escaneo completado. Resultados guardados en scan_results.log
tuusario@tumaquina:~# cat scan_results.log 
Puerto 443 abierto. Banner: No banner
Puerto 12345 abierto. Banner: SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3

#coded through OpenAI by @raulc0nes
