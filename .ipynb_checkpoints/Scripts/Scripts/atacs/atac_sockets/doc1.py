import socket
import struct

# Dirección IP de destino
target_ip = "127.0.0.1"

# Crear el socket raw
icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

# Estructura del paquete ICMP
icmp_type = 8  # Tipo de mensaje ICMP (8 para solicitud de eco)
icmp_code = 0  # Código para solicitud de eco
icmp_checksum = 0  # El checksum será calculado automáticamente por el kernel
icmp_id = 1234  # Identificador arbitrario
icmp_seq = 1  # Número de secuencia

# Estructura del paquete ICMP
icmp_header = struct.pack("BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

# Crear el checksum
def checksum(data):
    sum = 0
    for i in range(0, len(data), 2):
        sum += (data[i] << 8) + (data[i+1])
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    return (~sum) & 0xFFFF

# Crear el checksum para el encabezado ICMP
icmp_checksum = checksum(icmp_header)

# Estructura del paquete ICMP con el checksum actualizado
icmp_header = struct.pack("BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

# Dirección de destino
dest_addr = (target_ip, 0)

# Enviar el paquete ICMP
icmp_socket.sendto(icmp_header, dest_addr)

# Cerrar el socket
icmp_socket.close()

