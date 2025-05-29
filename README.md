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

---

## 🪪 Autor
U7Dani
 
🔗 https://www.linkedin.com/in/danielsánchezgarcía/
🐙 https://github.com/U7Dani

---

## 📄 Licencia

MIT License
