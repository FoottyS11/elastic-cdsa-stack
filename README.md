# 🔍 Elastic CDSA Stack + Forensic Uploader

<div align="center">

![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.11.3-00BFB3?style=for-the-badge&logo=elasticsearch)
![Kibana](https://img.shields.io/badge/Kibana-8.11.3-E8478B?style=for-the-badge&logo=kibana)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker)

**Plateforme automatisée d'ingestion et d'analyse de logs forensiques (EVTX, JSON, CSV)**
*Spécialement conçue pour les challenges Sherlock HackTheBox & Certification CDSA*

[🚀 Démarrage Rapide](#-démarrage-rapide) • [✨ Fonctionnalités](#-fonctionnalités) • [🔧 Architecture](#-architecture) • [📖 Guide](#-guide-dutilisation)

</div>

---

## 🎯 À propos

Ce projet est une **stack Elastic complète et pré-configurée** accompagnée d'une **Webapp d'ingestion intelligente**. Elle permet d'analyser des preuves forensiques en quelques secondes sans configuration complexe de Logstash ou Winlogbeat.

**Pourquoi cet outil ?**  
Lors de challenges CTF (Blue Team) ou d'investigations, on perd souvent du temps à configurer l'ingestion des logs. Cet outil automatise tout : de l'extraction des ZIP chiffrés à la création des Data Views dans Kibana.

---

## ✨ Fonctionnalités Clés

### 📤 Forensic Uploader (Nouveau!)
- **Interface Drag & Drop** moderne et rapide.
- **Support Multi-Formats** :
  - ✅ **EVTX** (Windows Event Logs) : Conversion XML automatique.
  - ✅ **ZIP** : Extraction automatique (support des archives chiffrées).
  - ✅ **JSON / CSV / LOG** : Parsing intelligent.
  - ✅ **MEM / RAW / VMEM / DMP** : Analyse mémoire avec Volatility3 (NEW!)
- **Gestion des Mots de Passe** : Détection des ZIP chiffrés et presets intégrés (`hacktheblue`, `hackthebox`, `infected`).
- **Feedback Temps Réel** : Barre de progression asynchrone détaillée ("Traitement fichier 5/12...").
- **Automatisation Kibana** : Création automatique du **Data View** et lien direct vers les logs.

### 🧠 Memory Forensics (Volatility3)
- **Analyse automatique** des dumps mémoire Windows (.mem, .raw, .vmem, .dmp)
- **Plugins intégrés** :
  - `pslist` : Liste des processus en cours
  - `netscan` : Connexions réseau actives
  - `cmdline` : Arguments de ligne de commande des processus
- **Indexation Elasticsearch** : Tous les artefacts mémoire indexés et cherchables dans Kibana

### 📊 SIEM Dashboards Pré-Configurés (NEW!)
4 dashboards prêts à l'emploi pour la certification CDSA :

| Dashboard | Description |
|-----------|-------------|
| 🔐 **Windows Security** | Logons (4624/4625), Process Creation (4688), Failed Auth |
| 🔄 **Lateral Movement** | PsExec, RDP (Type 10), WMI, SMB, Named Pipes |
| 🔒 **Persistence** | Scheduled Tasks, Service Installs, Registry Run Keys |
| 💻 **PowerShell Analysis** | ScriptBlock (4104), Encoded Commands, Suspicious Keywords |

### 🛡️ Elastic Stack (CDSA Ready)
- **Elasticsearch & Kibana 8.11** : Dernière version stable.
- **Logstash** : Pipeline configuré pour le routage dynamique des index.
- **Optimisé** : Configuration "Single Node" légère pour tourner sur un laptop (4-8GB RAM).

---

## 🔧 Architecture

Une architecture micro-services orchestrée par Docker Compose :

```mermaid
graph LR
    User[🕵️ Analyste] -->|Upload ZIP/EVTX| Web[🐍 Forensic Uploader<br/>(Flask + Python-EVTX)]
    
    subgraph Docker Network
        Web -->|TCP JSON| LS[🔧 Logstash]
        LS -->|Indexation| ES[💾 Elasticsearch]
        ES <-->|Query/Dashboards| KB[📊 Kibana]
    end
    
    Web -->|API Call| KB
```

| Service | Port | Rôle |
|---------|------|------|
| **Forensic Uploader** | `8080` | Interface web d'importation et parsing Python. |
| **Kibana** | `5601` | Visualisation, Dashboards, SIEM. |
| **Elasticsearch** | `9200` | Moteur de recherche et stockage. |
| **Logstash** | `5000` | Pipeline d'ingestion TCP. |

---

## 🚀 Démarrage Rapide

### Prérequis
- **Docker** et **Docker Compose**.
- 4GB de RAM minimum alloués à Docker.

### Installation

```bash
# 1. Cloner le projet
git clone https://github.com/FoottyS11/elastic-cdsa-stack.git
cd elastic-cdsa-stack

# 2. Lancer la stack (Build automatique)
./scripts/start.sh
```

> **Note**: Le premier démarrage peut prendre 2-3 minutes le temps de builder l'image webapp et d'initialiser Elasticsearch.

---

## 📖 Guide d'Utilisation

### 1️⃣ Importer des preuves (Sherlocks)

1. Ouvrez l'interface : **http://localhost:8080**
2. Glissez votre fichier **ZIP** (ex: `Sherlock-X.zip`) ou vos fichiers **EVTX**.
3. Si le ZIP est protégé, une fenêtre vous demandera le mot de passe (cliquez sur les presets pour aller plus vite !).
4. Laissez la moulinette tourner. La barre de progression vous indique l'avancement.

### 2️⃣ Analyser dans Kibana

1. Une fois l'import terminé, cliquez sur **"🔎 Ouvrir dans Kibana"**.
2. Vous atterrissez directement dans **Discover** sur le bon index.
3. Commencez vos requêtes KQL !

**Exemples de requêtes KQL utiles :**
```kql
# Trouver les processus suspects
event.code: "4688" AND process.name: "powershell.exe"

# Connexions RDP
event.code: "4624" AND winlog.logon.type: "10"

# Commandes encodées en Base64
process.command_line: *base64*
```

---

## 🛠️ Commandes Utiles

Seulement 3 scripts dans le dossier `./scripts/` :

- **Démarrer** : `./scripts/start.sh` (📊 importe automatiquement les dashboards SIEM)
- **Arrêter** (en gardant les données) : `./scripts/stop.sh`
- **Réinitialiser** (TOUT effacer) : `./scripts/reset.sh` (⚠️ Destructif !)

---

## 👤 Auteur

**CyberLama**  
*Étudiant en Cybersécurité - En route vers la certification CDSA*

---

<div align="center">
Made with ❤️ for the DFIR Community
</div>
