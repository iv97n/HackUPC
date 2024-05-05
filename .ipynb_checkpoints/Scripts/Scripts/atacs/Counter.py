import threading
import time
from scapy.all import *

# Función para sumar los datos de cada tipo de protocolo en la ventana de tiempo
def sumar_ventana(datos):
    suma_tcp = sum(d[0] for d in datos)
    suma_udp = sum(d[1] for d in datos)
    
    print(f"Suma de los últimos 3 segundos - TCP: {suma_tcp}, UDP: {suma_udp}")

# Función para crear la ventana de tiempo y procesar los datos cada 3 segundos
def procesar_datos():
    datos = []
    while True:
        # Simular la obtención de datos (aquí deberías obtener tus datos en tiempo real)
        dato = obtener_dato()
        datos.append(dato)
        
        # Si han pasado 3 segundos, procesar los datos y reiniciar la ventana
        if len(datos) == 3:
            sumar_ventana(datos)
            datos = []
        
        time.sleep(1)  # Esperar 1 segundo antes de obtener el siguiente dato

# Función para obtener datos de tráfico de red en tiempo real
def obtener_dato():
    
    # Filtrar paquetes TCP y contarlos
    tcp_paquetes = len(sniff(filter="tcp", timeout=1, iface="eth0"))
    
    # Filtrar paquetes UDP y contarlos
    udp_paquetes = len(sniff(filter="udp", timeout=1, iface="eth0"))
    
    return tcp_paquetes, udp_paquetes

# Crear un hilo para procesar los datos
hilo_procesamiento = threading.Thread(target=procesar_datos)
hilo_procesamiento.start()
