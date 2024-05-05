import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from sklearn.datasets import make_blobs
from sklearn.cluster import KMeans
import numpy as np

st.title('NET TRAFFIC ANALYSIS')

st.subheader("             Is someone attacking us")
st.subheader("             Do you trust everyone?")

st.set_option('deprecation.showPyplotGlobalUse', False)

# Título
st.subheader('WHO WE ARE?')

col1, col2, col3 = st.columns(3)

with col1:
    st.subheader('MARTI')
    image1 = "f1.png"
    st.image(image1, caption='Programador 1', use_column_width=True)

with col2:
    st.subheader('MARCEL')
    image2 = "f2.jpeg"
    st.image(image2, caption='Programador 2', use_column_width=True)

with col3:
    st.subheader('IVAN')
    image3 = "f3.jpeg"
    st.image(image3, caption='Programador 3', use_column_width=True)

# Title
st.subheader('Explanation of Packet Processing Code')


st.write("Now we just need to excecute the scripts to generate noisy data")

imageAttack = "atac.jpeg"
st.image(imageAttack, caption='Attack', use_column_width=True)

imageW = "Wireshark.jpeg"
st.image(imageW, caption='WIRESHARK', use_column_width=True)


st.subheader("SLIDING WINDOW PROCESS TO HAVE REAL TIME DATA")

imageWi = "window.jpeg"
st.image(imageWi, caption='PROCESSING', use_column_width=True)

st.subheader("TRAIN DATA!")
st.write("Just a representation on 3D to obtain the main essence")
imageF = "foto1.jpeg"
st.image(imageF, caption='Data', use_column_width=True)


col1, col2,= st.columns(2)

with col1:
    st.subheader('Outliers? View 1')
    image1 = "foto2.jpeg"
    st.image(image1, caption='figure 1', use_column_width=True)

with col2:
    st.subheader('View 2')
    image2 = "foto3.jpeg"
    st.image(image2, caption='figure 2', use_column_width=True)

    

st.subheader('We have developed an IDS to detect anomalies within the network or system of a company or any site')
imageD = "foto5.jpeg"
st.image(imageD, caption='Analysis', use_column_width=True)



import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Función para generar direcciones IP aleatorias en formato IPv4
def generate_ip():
    return ".".join(str(np.random.randint(0,256)) for _ in range(4))

# Función para generar números de puerto aleatorios
def generate_port():
    return np.random.randint(1, 65536)

# Función para generar un protocolo aleatorio (TCP/UDP)
def generate_protocol():
    return np.random.choice(["TCP", "UDP"])

# Función para generar el número de warnings aleatorios
def generate_warnings():
    return np.random.randint(0, 10)

# Generar datos aleatorios
num_records = 100
data = {
    "IP": [generate_ip() for _ in range(num_records)],
    "Port": [generate_port() for _ in range(num_records)],
    "Protocol": [generate_protocol() for _ in range(num_records)],
    "Warnings": [generate_warnings() for _ in range(num_records)]
}

# Crear DataFrame
df = pd.DataFrame(data)
# Título de la aplicación
st.title("Visualización de datos de red")

top_warnings = df.nlargest(10, 'Warnings')

st.subheader("Top 10 Registros con Más Warnings")
st.table(top_warnings)


# Función para generar direcciones IP aleatorias en formato IPv4
def generate_ip(region):
    if region == "USA":
        return f"192.168.{np.random.randint(0,256)}.{np.random.randint(0,256)}"
    elif region == "ASIA":
        return f"10.0.{np.random.randint(0,256)}.{np.random.randint(0,256)}"
    elif region == "PAKISTAN":
        return f"172.16.{np.random.randint(0,256)}.{np.random.randint(0,256)}"

# Generar datos aleatorios de direcciones IP y sus regiones
num_records = 500
regions = np.random.choice(["USA", "ASIA", "PAKISTAN"], size=num_records)
data = {
    "IP": [generate_ip(region) for region in regions],
    "Region": regions
}

# Crear DataFrame
df = pd.DataFrame(data)

# Título de la aplicación
st.title("Distribución de Direcciones IP por Región")

# Crear gráfico de barras apiladas
plt.figure(figsize=(10, 6))
sns.countplot(data=df, x='Region', palette='viridis')
plt.title("Distribución de Direcciones IP por Región")
plt.xlabel("Región")
plt.ylabel("Cantidad de Direcciones IP")
st.pyplot()


# Generar datos de IPs y conexiones
data = {
    "IP": ["192.168.93.2", "162.168.93.213", "198.162.91.34", "122.165.93.2", "162.165.93.72",
           "192.168.93.15", "162.168.93.211", "198.162.91.36", "122.165.93.5", "162.165.93.77",
           "192.168.93.7", "162.168.93.212", "198.162.91.38", "122.165.93.9", "162.165.93.73",
           "192.168.93.20", "162.168.93.215", "198.162.91.40", "122.165.93.14", "162.165.93.75",
           "192.168.93.25", "162.168.93.217", "198.162.91.42", "122.165.93.19", "162.165.93.78",
           "192.168.93.28", "162.168.93.219", "198.162.91.44", "122.165.93.22", "162.165.93.79"],
    "Conexiones": [713, 13, 513, 1713, 4715,
                   430, 8, 348, 1552, 3912,
                   593, 10, 472, 1935, 5218,
                   821, 14, 624, 2773, 6321,
                   943, 15, 792, 3681, 7325,
                   1123, 20, 913, 4615, 8501]
}

# Crear DataFrame
df = pd.DataFrame(data)

# Título de la aplicación
st.title("Visualización de datos de red")

# Graficar las conexiones por IP
plt.figure(figsize=(10, 8))
plt.barh(df['IP'], df['Conexiones'], color='skyblue')
plt.xlabel('Número de Conexiones')
plt.ylabel('IP')
plt.title('Número de Conexiones por IP')
plt.gca().invert_yaxis()  # Invertir el eje y para que la IP con más conexiones esté en la parte superior
st.pyplot()