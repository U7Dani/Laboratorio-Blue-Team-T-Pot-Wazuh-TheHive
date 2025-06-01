![image](https://github.com/user-attachments/assets/ba185aa1-c9cf-4488-8d79-c1024a197e36)

# 🛡️ Laboratorio Blue Team: T-Pot + Wazuh + TheHive (2025)

Simulación avanzada de un entorno de ciberseguridad defensiva con honeypots reales (T-Pot), un SIEM funcional (Wazuh) y futura integración con un SOAR (TheHive).

---

## 📌 Descripción del Proyecto

Este laboratorio permite experimentar detección, análisis y respuesta a incidentes con tráfico real en tiempo real. Se integra un sistema de honeypots con un pipeline de recolección y correlación de logs, generando alertas automáticas y visualizables desde un dashboard centralizado.

---

## ⚙️ Tecnologías Usadas

- **T-Pot (Honeypots + Suricata)**
- **Wazuh 4.12 (SIEM)**
- **Filebeat + Logstash (Pipeline de Logs)**
- **TheHive (SOAR, integración futura)**
- **VPS Linux (Contabo)**
- **Elastic Stack (Visualización)**

---

## 🧩 Arquitectura del Entorno

```
[ Atacantes reales ]
        ↓
     [T-Pot]
  Honeypots + Suricata
        ↓
  Logs + JSON (eve.json)
        ↓
    Filebeat → Logstash
        ↓
     [Wazuh SIEM]
→ Alertas + Dashboards
        ↓
  (Próximamente TheHive)
```

---

## 📁 Estructura del Proyecto

```
📂 tpot-wazuh-lab/
├── README.md
├── wazuh/
│   └── local_rules.xml
├── tpot/
│   ├── ossec.conf
│   └── filebeat.yml
├── logstash/
│   └── suricata.conf
├── docs/
│   └── arquitectura.png
│   └── dashboard-wazuh.png
```

---

## 🛠️ Instalación Rápida
![image](https://github.com/user-attachments/assets/4bb0ab11-07ad-49e1-9100-70a58bfcdb83)
![image](https://github.com/user-attachments/assets/11d579a4-493e-4e2b-bb95-a58e1394139a)
![image](https://github.com/user-attachments/assets/8f31f2e6-2407-4dfa-a60d-ee80e7a02a81)
![image](https://github.com/user-attachments/assets/16b9e587-c5ab-46d8-8032-21a7f9f6b562)
![image](https://github.com/user-attachments/assets/d3461965-556c-47fb-8c4b-dc8966ec6513)

### 1. Acceso a T-Pot

```bash
ssh -p xxxxx pruebas@xxx.xxx.xxx.xxx
```

### 2. Instalar Wazuh
![image](https://github.com/user-attachments/assets/3353459b-42ac-4d99-ba3b-aa9277db089f)
![image](https://github.com/user-attachments/assets/70cf85bb-ad94-4e5f-b58a-6676c6b52d15)


```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
bash wazuh-install.sh -a
```

### 3. Configurar Agente Wazuh en T-Pot
![image](https://github.com/user-attachments/assets/f8381762-e124-4166-a251-d6ca04eda1c4)

```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb
sudo dpkg -i wazuh-agent_4.12.0-1_amd64.deb
```

Editar `/var/ossec/etc/ossec.conf` y luego:

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

### 4. Configurar Filebeat + Logstash

- Editar `filebeat.yml` y `suricata.conf`
- Verificar recepción en Kibana

---

## 🔍 Reglas Personalizadas

Archivo: `wazuh/local_rules.xml`

```xml
<rule id="100010" level="10">
  <if_sid>18107</if_sid>
  <match>ET SCAN</match>
  <description>Suricata: Escaneo SSH detectado</description>
  <group>suricata</group>
</rule>
```

---

## 📊 Visualización en Wazuh

Filtro en Kibana:

```kql
agent.name: "T-pot"
```

---

## ✅ Resultado

- Los ataques reales contra T-Pot generan alertas automáticas.
- El flujo está 100% funcional de honeypot a dashboard.
- Preparado para ampliar a respuestas automáticas con TheHive.
# 📡 Monitoreo del Honeypot T-Pot con Wazuh

Este repositorio documenta la configuración, actividad y lógica de detección de un **honeypot T-Pot** desplegado en un endpoint monitoreado, con logs recolectados y analizados por **Wazuh**.

---

## 🧾 Descripción General

**T-Pot** es una plataforma honeypot de múltiples componentes desarrollada por Telekom, que combina varios servicios honeypot (por ejemplo, Cowrie, Dionaea, Honeytrap) en contenedores Docker. El objetivo es capturar, analizar y responder a actividades maliciosas dirigidas a servicios expuestos.

**Wazuh** se utiliza aquí para la agregación de logs y correlación de eventos de seguridad. Una alerta específica (Regla ID `533`) monitorea cambios en los puertos abiertos (basado en `netstat`) y detecta puertos nuevos o cerrados.

---

## ⚙️ Metadatos del Sistema

| Atributo         | Valor                |
|------------------|----------------------|
| **ID del Agente**| `001`                |
| **IP del Agente**| `158.220.117.62`     |
| **Nombre del Agente**| `T-pot`          |
| **Nombre del Gestor**| `vmi2631881`     |
| **Decodificador**| `ossec`              |
| **Tipo de Entrada**| `log`              |
| **Fuente del Log**| `netstat listening ports` |
| **Regla Activada**| `533 - Estado de puertos en escucha cambiado` |
| **Nivel de Severidad**| 7              |
| **Veces Activada**| 9                   |
| **Fecha y Hora** | `2025-05-29 23:50:32`|

---

## 📊 Resumen de Actividad de Puertos

La alerta de Wazuh fue activada por la **adición y eliminación de puertos en escucha**, indicando reconfiguración del honeypot, rotación de servicios o posible interacción externa. Se observan las siguientes categorías:

### 🔓 Puertos Expuestos Comunes
Servicios altamente atacados expuestos por contenedores honeypot (`docker-proxy`):
- `22`, `23`, `25`, `80`, `81`, `443`, `445`, `465`, `587`, `631`, `993`, `995`, `1080`, `1433`, `3306`, `5432`, `5555`, `5900`, `6379`, `8080`, `8443`, `9200`, `27017`

### 🧪 Puertos Manejados por Honeytrap
Honeytrap simula una amplia gama de servicios TCP:
- Puertos `1028`, `1963`, `2152`, `2221`, `3380`–`3399`, `4475`, `5800`, `6935`, `7525`, `8051`, `8064`, `8108`, `9476`, `9994`, `9998`, `12309`, `13740`, `15434`, `18063`, `26411`, `26678`, `59283`, etc.

Estos simulan sistemas reales (RDP de Windows, SCADA, IoT, C2) para atraer atacantes y registrar su comportamiento.

### 📌 Nota Especial: Puerto `64295` → `/usr`
Esto es una anomalía que puede indicar:
- Mala configuración
- Binario ejecutado desde `/usr`
- Artefacto del sistema de logs

---

## 🔐 Cumplimiento de Seguridad (Mapeo de Regla Wazuh)

Este evento se relaciona con múltiples estándares de cumplimiento:

| Estándar        | Códigos de Control                    |
|----------------|----------------------------------------|
| **PCI DSS**     | `10.2.7`, `10.6.1`                     |
| **HIPAA**       | `164.312(b)`                           |
| **NIST 800-53** | `AU-14`, `AU-6`                        |
| **TSC**         | `CC6.8`, `CC7.2`, `CC7.3`              |
| **GPG13**       | `10.1`                                 |
| **GDPR**        | `IV_35.7.d`                            |

---

## 🔄 Resumen de Comportamiento

Esta alerta sugiere:
- Rotación activa o escalado automático de puertos del honeypot
- Activación de servicios por tráfico entrante
- Posibles intentos de reconocimiento o explotación por atacantes

---

## 🔧 Recomendaciones

1. **Enriquecimiento de Logs**:
   - Integrar Wazuh con inteligencia de amenazas (por ejemplo, AbuseIPDB, MISP)
   - Correlacionar IPs, comandos y puertos en Kibana

2. **Aseguramiento del Sistema**:
   - Validar el aislamiento de Docker (AppArmor, seccomp, namespaces)
   - Asegurar que no haya servicios reales expuestos

3. **Telemetría a Largo Plazo**:
   - Recopilar estadísticas históricas de puertos atacados
   - Identificar patrones de comportamiento de atacantes

---

## 🛠 Herramientas Involucradas

- **T-Pot** (plataforma honeypot)
- **Honeytrap** (honeypot TCP)
- **Docker** (aislamiento de servicios)
- **Wazuh** (SIEM y correlación de eventos)
- **Netstat** (monitoreo de puertos)
- **Regla OSSEC 533** (monitorea estado de puertos)

---

## 📁 Ejemplo de Registro (Log)

```text
tcp 0.0.0.0:1028 0.0.0.0:* 431510/honeytrap
tcp 0.0.0.0:443  0.0.0.0:* 4745/docker-proxy
tcp6 :::27017    :::*      5748/docker-proxy
tcp 0.0.0.0:5800 0.0.0.0:* 431049/honeytrap
tcp 0.0.0.0:64295 0.0.0.0:* /usr
```

---
![Captura de pantalla 2025-05-30 001312](https://github.com/user-attachments/assets/5de1f6a1-69bb-4a97-b12c-8afa474e44f3)
![Captura de pantalla 2025-05-30 001325](https://github.com/user-attachments/assets/d13a65c7-67d4-4214-bf88-0322f0161d64)

# 🧠 MITRE ATT&CK en el Laboratorio Wazuh + T-Pot

Este entorno documenta la integración del framework MITRE ATT&CK en un laboratorio defensivo compuesto por **Wazuh** como SIEM y **T-Pot** como plataforma de honeypots. Se muestra cómo correlacionar, visualizar y entender ataques reales mediante reglas MITRE enriquecidas.

---

## 🧠 ¿Qué es MITRE ATT&CK?

**MITRE ATT&CK** (Adversarial Tactics, Techniques & Common Knowledge) es un marco de referencia que documenta:

- Las **tácticas** utilizadas por los atacantes (lo que quieren lograr).
- Las **técnicas** con las que lo hacen (cómo lo logran).
- Ejemplos reales basados en inteligencia de amenazas.

---

## 🎯 ¿Para qué lo usamos en el laboratorio?

- Correlacionar alertas de Wazuh con **tácticas y técnicas MITRE**.
- Visualizar ataques como `Password Guessing`, `Brute Force`, `SSH`, `Data Destruction`, etc.
- Enriquecer dashboards para **Threat Hunting**.
- Facilitar el envío automático a **TheHive** cuando se detectan técnicas específicas.
- Aplicar contramedidas basadas en las recomendaciones del framework (Mitigations).

---

## 📊 ¿Cómo se visualiza en Wazuh?

Wazuh permite visualizar MITRE ATT&CK desde múltiples ángulos:

- **Dashboards** con evolución temporal por técnica y táctica.
- **Distribución por agentes** (honeypots vs endpoints).
- **Paneles de inteligencia** para aplicar mitigaciones.
- **Exploración táctica** completa con IDs MITRE como `T1110.001`, `T1021.004`, etc.

---

## 📸 Visualizaciones del laboratorio

### 1. Evolución y distribución por táctica/técnica

Se observa la evolución en el tiempo de ataques clasificados por MITRE, destacando técnicas como `Password Guessing` y tácticas como `Credential Access` y `Lateral Movement`. También se muestran los agentes involucrados.
![Captura de pantalla 2025-05-31 000708](https://github.com/user-attachments/assets/c3b44af1-9e98-4541-808a-2192f461bef6)

---

### 2. Panel de Mitigaciones

Sección de **Mitigations** con recomendaciones específicas para contrarrestar cada técnica, como configuración de GPOs, restricciones de ejecución, antivirus o segmentación de red.
![Captura de pantalla 2025-05-31 000724](https://github.com/user-attachments/assets/883eaa52-bb93-4fcb-b3a5-71796099062b)

---

### 3. Framework MITRE completo

Visualización completa de tácticas y técnicas con contador de alertas. Permite identificar las técnicas más explotadas en el entorno (`T1110`, `T1021.004`, `T1485`, etc.).

![Captura de pantalla 2025-05-31 000738](https://github.com/user-attachments/assets/c0d2a17f-8a75-4f8e-97c7-027650e093e0)

---


### 4. Vista detallada de eventos

Muestra eventos individuales asociados a MITRE: `agent.name`, `rule.mitre.id`, `description`, `rule.level`, ideal para análisis forense.
![Captura de pantalla 2025-05-31 000752](https://github.com/user-attachments/assets/378cb5df-b18b-479c-b941-630d0bd1f03a)

---

### 5. Threat Hunting overview

Resumen general del entorno: volumen total de alertas, autenticaciones fallidas, agentes involucrados, alertas por severidad y técnicas MITRE más frecuentes.
![Captura de pantalla 2025-05-31 000804](https://github.com/user-attachments/assets/8966ce3c-7be5-4d57-84c1-46612f8f11e0)

---

### 6. Logs enriquecidos con MITRE y severidad

Exploración de logs enriquecidos con niveles (`rule.level`), descripciones (`sshd: authentication failed`), IDs MITRE (`T1110.001`), etc.
![Captura de pantalla 2025-05-31 000818](https://github.com/user-attachments/assets/e3efa982-d492-4a9e-a6b9-b323b0816b30)

---

### 7. Panel de vulnerabilidades

Complementa el análisis con información sobre CVEs presentes en el sistema (ej. `CVE-2025-3576`) y paquetes afectados, conectando amenazas detectadas con vulnerabilidades reales.
![Captura de pantalla 2025-05-31 000832](https://github.com/user-attachments/assets/009fa6d9-be80-4559-9e35-4aaa6ac4d868)

---

## 🧩 Resultado

Gracias a esta integración, el laboratorio ahora cuenta con una vista integral de los ataques detectados, categorizados bajo el marco MITRE, facilitando la investigación, visualización y respuesta.

Este entorno puede ampliarse con:
- Envío automático a TheHive vía Webhook
- Dashboards personalizados
- Automatización de respuestas según MITRE tactic detectada


# 🚀 Integración de TheHive en Laboratorio de Ciberseguridad (Wazuh + T-Pot + TheHive)

## 🧩 Arquitectura del laboratorio

| Componente | Función                                   | Ejemplo de acceso              |
|------------|-------------------------------------------|--------------------------------|
| 🐝 TheHive  | SOAR (gestión de alertas e incidentes)    | http://<thehive-ip>:9000       |
| 📈 Wazuh    | SIEM (detección y generación de alertas)  | https://<wazuh-ip>             |
| 🪤 T-Pot    | Honeypots con Suricata y ELK              | <tpot-ip>                      |

---

## 1️⃣ Preparación del entorno

### 🔸 Requisitos mínimos

- Ubuntu 22.04 LTS
- Docker y Docker Compose
- Usuario con permisos sudo
- Conexión a Internet

![image](https://github.com/user-attachments/assets/0dd9172a-0dda-440b-ba65-576bf7bda364)
![image](https://github.com/user-attachments/assets/f28ca23e-ec76-4e42-8c1e-7e8a34b681aa)
![image](https://github.com/user-attachments/assets/7f4f0ecd-3ad9-4e8d-aedd-618d30447e0a)

---

## 2️⃣ Instalación de TheHive con Docker

```bash
# 1. Crear usuario de trabajo (opcional)
sudo adduser thehiveuser
sudo usermod -aG sudo thehiveuser
su - thehiveuser

# 2. Instalar Docker y Docker Compose
sudo apt update && sudo apt install -y docker.io docker-compose
sudo systemctl enable docker

# 3. Crear directorio de trabajo
mkdir ~/thehive && cd ~/thehive
```

---

## 📄 docker-compose.yml

Guarda este archivo como `docker-compose.yml` en el directorio `~/thehive/`:

```yaml
version: "3.7"
services:
  cassandra:
    image: cassandra:3
    container_name: cassandra
    networks:
      - thehive
    volumes:
      - cassandra-data:/var/lib/cassandra
    environment:
      - MAX_HEAP_SIZE=512M
      - HEAP_NEWSIZE=100M

  thehive:
    image: strangebee/thehive:5
    container_name: thehive
    depends_on:
      - cassandra
    ports:
      - "9000:9000"
    networks:
      - thehive
    volumes:
      - thehive-data:/opt/thehive/data
      - thehive-config:/opt/thehive/conf
    environment:
      - CASSANDRA_CONTACT_POINT=cassandra
      - START_WAIT_FOR_CASSANDRA=true

networks:
  thehive:

volumes:
  cassandra-data:
  thehive-data:
  thehive-config:
```

### ▶️ Arranque

```bash
docker compose up -d
```

---

## 3️⃣ Configuración inicial de TheHive

1. Accede a `http://<tu-ip>:9000`
2. Crea el primer usuario administrador
3. Configura la organización y genera una API Key (no la publiques)

---

## 4️⃣ Integración de alertas desde Wazuh

### 🧪 Método: Webhook + Script Python personalizado

#### 📄 Script Python personalizado

Guarda este script como `/var/ossec/integrations/custom-w2thive.py` en el servidor de Wazuh:

```python
#!/usr/bin/env python3
import json
import sys
import requests

def send_alert_to_thehive(alert):
    url = "http://<THEHIVE_IP>:9000/api/alert"  # Sustituye con tu IP privada o localhost
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer <YOUR_API_KEY>"  # Sustituye con tu clave privada
    }
    response = requests.post(url, headers=headers, data=json.dumps(alert), verify=False)
    print(response.status_code, response.text)

if __name__ == "__main__":
    alert = json.load(sys.stdin)
    send_alert_to_thehive(alert)
```

💡 Asegúrate de que el script tenga permisos de ejecución:
```bash
chmod +x /var/ossec/integrations/custom-w2thive.py
```

---

### ⚙️ Fragmento para `ossec.conf`

Edita el archivo `/var/ossec/etc/ossec.conf` y añade dentro de `<ossec_config>`:

```xml
<integration>
  <name>custom-w2thive.py</name>
  <hook_url>http://localhost:9000/api/alert</hook_url>
  <level>5</level>
  <alert_format>json</alert_format>
</integration>
```

Reinicia Wazuh para aplicar los cambios:

```bash
sudo systemctl restart wazuh-manager
```

---

## 5️⃣ Verificación

- Lanza un ataque de prueba desde T-Pot (por ejemplo, escaneo Nmap)
- Observa la alerta en Wazuh
- Confirma que llega automáticamente a TheHive
- Comprueba que se clasifica correctamente con campos como `severity`, `agent`, `rule.id`, etc.

---

## 6️⃣ (Opcional) Persistencia del contenedor

Para que TheHive se reinicie automáticamente tras apagado del sistema:

```bash
docker update --restart unless-stopped thehive
```

---

## 📁 Sugerencia de estructura del repositorio

```
thehive-integration-lab/
├── docker/
│   └── docker-compose.yml
├── docs/
│   └── README.md
│   └── ossec.conf
│   └── custom-w2thive.py
```

---

## ✅ Notas finales

- Sustituye `<THEHIVE_IP>` y `<YOUR_API_KEY>` en tus archivos.
- No publiques nunca tu API Key ni IP pública en GitHub.
- Puedes mejorar el script para ejecutar acciones según severidad, integrarlo con MISP, Cortex, etc.

---



## 📌 Licencia

Esta documentación se proporciona bajo la Licencia MIT. T-Pot está disponible bajo su propia licencia de código abierto en [https://github.com/telekom-security/tpotce](https://github.com/telekom-security/tpotce).


---

## 🪪 Autor
U7Dani
 
🔗 https://www.linkedin.com/in/danielsánchezgarcía/
🐙 https://github.com/U7Dani

---

## 📄 Licencia

MIT License
