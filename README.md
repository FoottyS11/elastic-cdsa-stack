# 🔍 Stack Elastic CDSA

Stack Elastic complète dockerisée pour l'analyse et la centralisation de logs - idéale pour les activités CDSA (Cybersecurity Defense & Security Analysis).

![Elastic Stack](https://img.shields.io/badge/Elastic-8.11.3-005571?style=for-the-badge&logo=elastic&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

## 📋 Table des matières

- [🎯 Fonctionnalités](#-fonctionnalités)
- [🏗️ Architecture](#️-architecture)
- [📦 Composants](#-composants)
- [🚀 Installation rapide](#-installation-rapide)
- [⚙️ Configuration](#️-configuration)
- [📊 Accès aux interfaces](#-accès-aux-interfaces)
- [📝 Import de logs](#-import-de-logs)
- [🔧 Commandes utiles](#-commandes-utiles)
- [🛡️ Cas d'usage CDSA](#️-cas-dusage-cdsa)
- [❓ FAQ](#-faq)

## 🎯 Fonctionnalités

- ✅ **Stack complète** : Elasticsearch, Kibana, Logstash, Filebeat, Metricbeat
- ✅ **Fleet Server** : Gestion centralisée des agents Elastic
- ✅ **Sécurité** : Authentification activée par défaut
- ✅ **Multi-sources** : TCP, UDP, Syslog, Beats, HTTP API
- ✅ **Parsing avancé** : SSH, Sudo, Apache, Nginx, Windows Events
- ✅ **Monitoring** : Métriques système, Docker, et stack Elastic
- ✅ **Prêt pour la production** : Health checks, restart policies, volumes persistants

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SOURCES DE LOGS                          │
│  (Syslog, Applications, Agents, API HTTP)                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
         ▼            ▼            ▼
┌─────────────┐ ┌──────────┐ ┌──────────────┐
│  LOGSTASH   │ │ FILEBEAT │ │ METRICBEAT   │
│  Port 5044  │ │          │ │              │
│  Port 5000  │ │          │ │              │
└──────┬──────┘ └────┬─────┘ └──────┬───────┘
       │             │              │
       └─────────────┼──────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │    ELASTICSEARCH      │
         │      Port 9200        │
         │   (Stockage & Index)  │
         └───────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌────────────────┐
│     KIBANA      │     │  FLEET SERVER  │
│    Port 5601    │     │   Port 8220    │
│ (Visualisation) │     │  (Gestion)     │
└─────────────────┘     └────────────────┘
```

## 📦 Composants

| Composant | Version | Port | Description |
|-----------|---------|------|-------------|
| **Elasticsearch** | 8.11.3 | 9200 | Moteur de recherche et stockage |
| **Kibana** | 8.11.3 | 5601 | Interface web de visualisation |
| **Logstash** | 8.11.3 | 5044, 5000 | Pipeline de traitement de données |
| **Filebeat** | 8.11.3 | - | Collecteur de logs fichiers |
| **Metricbeat** | 8.11.3 | - | Collecteur de métriques |
| **Fleet Server** | 8.11.3 | 8220 | Gestion centralisée des agents |

## 🚀 Installation rapide

### Prérequis

- Docker & Docker Compose
- 4 GB RAM minimum (8 GB recommandé)
- 20 GB d'espace disque

### Étapes

```bash
# 1. Cloner le repository
git clone https://github.com/VOTRE_USERNAME/elastic-cdsa-stack.git
cd elastic-cdsa-stack

# 2. (Optionnel) Personnaliser la configuration
nano .env

# 3. Configurer le système pour Elasticsearch
sudo sysctl -w vm.max_map_count=262144

# 4. Lancer la stack
docker-compose up -d

# 5. Attendre le démarrage (~2-3 minutes)
docker-compose logs -f

# 6. Accéder à Kibana
# http://localhost:5601
# Login: elastic / changeme123
```

### Script automatique

```bash
# Rendre les scripts exécutables
chmod +x scripts/*.sh

# Démarrer
./scripts/start.sh

# Arrêter
./scripts/stop.sh

# Réinitialiser (supprime toutes les données)
./scripts/reset.sh
```

## ⚙️ Configuration

### Variables d'environnement (.env)

```bash
# Version Elastic
ELASTIC_VERSION=8.11.3

# Mots de passe (À CHANGER EN PRODUCTION!)
ELASTIC_PASSWORD=changeme123
KIBANA_PASSWORD=changeme123

# Ressources mémoire
ES_JAVA_OPTS=-Xms1g -Xmx1g
LS_JAVA_OPTS=-Xms512m -Xmx512m

# Ports
ES_PORT=9200
KIBANA_PORT=5601
LOGSTASH_BEATS_PORT=5044
LOGSTASH_TCP_PORT=5000
```

### Configuration mémoire recommandée

| RAM Disponible | ES_JAVA_OPTS | LS_JAVA_OPTS |
|----------------|--------------|--------------|
| 4 GB | -Xms512m -Xmx512m | -Xms256m -Xmx256m |
| 8 GB | -Xms1g -Xmx1g | -Xms512m -Xmx512m |
| 16 GB+ | -Xms2g -Xmx2g | -Xms1g -Xmx1g |

## 📊 Accès aux interfaces

| Service | URL | Identifiants |
|---------|-----|--------------|
| **Kibana** | http://localhost:5601 | elastic / changeme123 |
| **Elasticsearch** | http://localhost:9200 | elastic / changeme123 |
| **Logstash API** | http://localhost:9600 | - |

## 📝 Import de logs

### 1. Via Filebeat (Automatique)

Filebeat collecte automatiquement les logs depuis :
- `/var/log/syslog`
- `/var/log/auth.log`
- `/var/log/apache2/*`
- `/var/log/nginx/*`
- Conteneurs Docker

### 2. Via Logstash TCP/UDP

```bash
# Envoyer des logs en JSON via TCP
echo '{"message":"Test log","severity":"info"}' | nc localhost 5000

# Envoyer des logs via UDP
echo '{"message":"Test UDP"}' | nc -u localhost 5000
```

### 3. Via l'API HTTP de Logstash

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{"message":"Log via API","source":"test","level":"info"}'
```

### 4. Via Syslog

```bash
# Configurer rsyslog pour envoyer vers Logstash
# Ajouter dans /etc/rsyslog.conf :
*.* @localhost:5514
```

### 5. Upload de fichiers dans Kibana

1. Aller sur Kibana → **Machine Learning** → **Data Visualizer**
2. Cliquer sur **Upload file**
3. Glisser-déposer votre fichier (CSV, JSON, log)
4. Suivre l'assistant d'import

### 6. Via Fleet & Elastic Agent

1. Aller sur Kibana → **Fleet** → **Agent policies**
2. Créer une nouvelle policy
3. Ajouter des intégrations (Windows, Linux, etc.)
4. Déployer l'agent sur vos machines

## 🔧 Commandes utiles

```bash
# Voir les logs en temps réel
docker-compose logs -f

# Logs d'un service spécifique
docker-compose logs -f elasticsearch
docker-compose logs -f kibana

# Status des conteneurs
docker-compose ps

# Redémarrer un service
docker-compose restart logstash

# Arrêter la stack
docker-compose down

# Arrêter et supprimer les données
docker-compose down -v

# Voir l'utilisation des ressources
docker stats

# Shell dans un conteneur
docker exec -it elasticsearch bash
docker exec -it kibana bash

# Vérifier la santé d'Elasticsearch
curl -u elastic:changeme123 http://localhost:9200/_cluster/health?pretty

# Lister les index
curl -u elastic:changeme123 http://localhost:9200/_cat/indices?v
```

## 🛡️ Cas d'usage CDSA

### Analyse de logs d'authentification

La stack est préconfigurée pour détecter :
- 🔴 **Échecs SSH** : Tentatives de connexion échouées
- 🟢 **Connexions SSH réussies** : Authentifications valides
- 🟠 **Commandes sudo** : Escalade de privilèges
- 🔵 **Événements Windows** : Via Winlogbeat

### Dashboards suggérés

Dans Kibana, créez des visualisations pour :
1. **SSH Failed Logins Map** : Géolocalisation des attaques
2. **Authentication Timeline** : Chronologie des connexions
3. **Top Attackers** : IPs sources les plus actives
4. **Sudo Commands** : Historique des commandes privilégiées

### Requêtes KQL utiles

```kql
# Échecs SSH
tags: "ssh_failure"

# Connexions depuis une IP spécifique
src_ip: "192.168.1.100"

# Logs de sécurité
log_type: "ssh" OR log_type: "audit"

# Erreurs dans les dernières 24h
@timestamp >= now-24h AND level: "error"
```

## 📁 Structure du projet

```
elastic-cdsa-stack/
├── docker-compose.yml      # Configuration Docker
├── .env                    # Variables d'environnement
├── .gitignore             # Fichiers ignorés par Git
├── README.md              # Documentation
├── config/
│   ├── logstash/
│   │   ├── config/
│   │   │   └── logstash.yml
│   │   └── pipeline/
│   │       └── logstash.conf
│   ├── filebeat/
│   │   └── filebeat.yml
│   └── metricbeat/
│       └── metricbeat.yml
└── scripts/
    ├── start.sh           # Script de démarrage
    ├── stop.sh            # Script d'arrêt
    └── reset.sh           # Script de réinitialisation
```

## ❓ FAQ

### La stack ne démarre pas ?

```bash
# Vérifier les prérequis système
sudo sysctl -w vm.max_map_count=262144

# Pour le rendre permanent
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Elasticsearch refuse les connexions ?

Attendre 1-2 minutes que le service soit complètement démarré :
```bash
docker-compose logs -f elasticsearch
```

### Comment changer les mots de passe ?

1. Modifier le fichier `.env`
2. Recréer les conteneurs : `docker-compose up -d --force-recreate`

### Comment persister le vm.max_map_count ?

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Comment ajouter mes propres sources de logs ?

Modifier le fichier `config/logstash/pipeline/logstash.conf` et ajouter votre input personnalisé.

## 📄 Licence

MIT License - Utilisez librement pour vos projets CDSA!

---

**🔥 Bon hunting !** 🎯
