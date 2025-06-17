# Despliegue del Sistema IDS/IPS

Esta sección contiene todos los scripts, configuraciones y recursos necesarios para desplegar y poner en marcha el sistema IDS/IPS basado en Deep Learning desarrollado en el laboratorio `myLab`. Incluye la configuración y automatización de herramientas como Wazuh, Suricata, Fluent Bit y el entorno de red.

## [+] Contenido

### [>] Wazuh

- Configuraciones personalizadas para la plataforma SIEM Wazuh.  
- Reglas sobrescritas para integrar alertas generadas por el modelo de IA.  

### [>] Suricata
  
- Interfaz `ens33` configurada en modo promisc.  
- Timeouts personalizados para optimizar la detección.
- Salida de logs en formato eve.json

### [>] Fluent Bit (`td-agent-bit`)

- Configuración de Fluent Bit para leer logs de Suricata y Zeek.  
- Envío de logs procesados a los tópicos de Kafka (`suricata-flows` y `zeek-flows`).  
- Parsers personalizados para adaptar el formato de logs a la ingesta.

### [>] Networking

- Configuración de red para la máquina IDS/IPS basada en Ubuntu.  
- Ajustes para habilitar IP forwarding en mi laboratorio.  

### [>] Scripts de control y automatización

- `startConfiguration.sh`: Script para arrancar y reiniciar todos los servicios necesarios (Zookeeper, Kafka, Fluent Bit, Suricata, Zeek, AI consumidor).    
- `endConfiguration.sh`: Script para finalizar de manera ordenada los servicios activos y eliminar los bloqueos IP.
- `myVerbraucher.py`: Script consumidor de Kafka que procesa los flujos de red, aplica el modelo de IA y genera alertas.


## [+] Uso e instrucciones básicas

1. Modificar los archivos de configuración según el entorno de red (IPs, interfaces).  
2. Ejecutar `startConfiguration.sh` para iniciar toda la infraestructura de forma ordenada y automatizada.  
3. Monitorizar logs en `/var/log/` y archivos temporales `/tmp/` para verificar estado y errores.  
4. Consultar los logs generados por Wazuh para alertas SIEM y Suricata para eventos de red.  
5. Ajustar las reglas y parámetros de bloqueo dinámico según necesidades y tráfico detectado.

## [+] Debugging

- Logs principales se encuentran en `/tmp/` y `/var/log/` según el servicio.  
- `startConfiguration.sh` puede ejecutarse con la opción --debug para activar modo debug en el consumidor AI.  

## [+] Tecnologías utilizadas

- **Kafka / Zookeeper**: Middleware de mensajería en tiempo real.  
- **Fluent Bit**: Procesamiento y envío de logs.  
- **Suricata**: Sensor de red para detección de intrusiones.  
- **Zeek**: Análisis profundo de flujos de red.  
- **Wazuh**: Plataforma SIEM para detección, alertas y monitoreo.  
- **iptables**: Firewall para bloqueo dinámico de IPs. 
