# Palo Bajo - NIDS

Sistema para la detección y prevención de intrusiones en redes mediante la aplicación de técnicas avanzadas de deep learning.

**Nota:** Este sistema se centra principalmente en la detección de técnicas de **Active Scanning** según la matriz MITRE ATT&CK, especialmente la técnica [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/).

## [+] Resumen

Sistema IDS/IPS que utiliza un modelo de clasificación binaria basado en una red neuronal tipo Multilayer Perceptron (MLP), entrenado con tráfico de red realista. Integra captura de paquetes, análisis de flujos (Zeek, Suricata), procesamiento en tiempo real (Kafka, Fluent Bit) y alertas SIEM (Wazuh).

## [+] Prueba de concepto

## [+] Cómo usar

1. Clonar el repositorio:

```bash
git clone https://github.com/M0sky/Palo-Bajo-NIDS.git
cd Palo-Bajo-NIDS
```

2. Descargar archivos grandes con Git LFS:

```bash
git lfs install
git lfs pull
```

3. Configurar la topología en GNS3 (ver carpeta [`myLab`](./myLab/) y ZIP adjunto).
4. Preparar la máquina ubuntu donde se despliega el IDS/IPS, habiendo instalado y configurado las siguientes herramientas:
- **Apache Kafka y Zookeper**: Crear y configurar los tópicos zeek-flows y suricata-flows.
- **Fluent Bit**: Empleado para leer logs de Suricata y Zeek y enviarlos a Kafka. Archivo de configuración: [`deployment/fluent-bit/td-agent-bit.conf`](./deployment/fluent-bit/td-agent-bit.conf).
- **Suricata**: Utilizado para asegurar la consistencia de los flujos. Archivo de configuración: [`deployment/suricata/suricata.yaml`](./deployment/suricata/suricata.yaml).
- **Zeek**: Utilizado para análisis de flujos (TCP flags y estado de la conexion).
- **Wazuh**: Plataforma SIEM para monitorizar alertas.

5. Ejecutar el script de despliegue ([`deployment/startConfiguration.sh`](`deployment/startConfiguration.sh`).
6. Generar escaneos y ataques desde Kali Linux para probar el sistema.
7. Monitorizar alertas y eventos en Wazuh.

## [+] Estructura del repositorio

- `myLab/`: Topología en GNS3.
- `labeling/`: Pipeline para generación de datasets etiquetados a partir de capturas PCAP.
- `training/`: Scripts de preprocesado y entrenamiento del modelo binario.
- `deployment/`: Configuraciones y scripts para despliegue en tiempo real del sistema.