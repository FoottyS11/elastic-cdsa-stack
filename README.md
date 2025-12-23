# 🔍 Stack Elastic CDSA - Docker Compose

Stack Elastic complète et prête à l'emploi pour la **Certification DevSecOps Associate (CDSA)**. Cette stack inclut Elasticsearch, Kibana, Logstash, Filebeat, Metricbeat et Fleet Server pour la collecte, l'analyse et la visualisation de logs et métriques.

## 📋 Prérequis

- Docker 20.10+
- Docker Compose V2+
- 4GB RAM minimum (8GB recommandé)
- Ports disponibles: 5601, 9200, 5044, 8220

## 🚀 Démarrage rapide

\`\`\`bash
# Cloner le repo
git clone https://github.com/VOTRE_USERNAME/elastic-cdsa-stack.git
cd elastic-cdsa-stack

# Lancer la stack
sudo sysctl -w vm.max_map_count=262144
./scripts/start.sh

# Attendre 1-2 minutes que tous les services démarrent
\`\`\`

## 🌐 Accès aux services

| Service | URL | Credentials |
|---------|-----|-------------|
| **Kibana** | http://localhost:5601 | elastic / changeme123 |
| **Elasticsearch** | http://localhost:9200 | elastic / changeme123 |
| **Logstash** | http://localhost:9600 | - |
| **Fleet Server** | http://localhost:8220 | - |

## 🛠️ Commandes utiles

\`\`\`bash
# Démarrer la stack
./scripts/start.sh

# Arrêter la stack
./scripts/stop.sh

# Réinitialiser complètement (⚠️ supprime toutes les données)
./scripts/reset.sh

# Voir les logs
sudo docker compose logs -f [service_name]

# Vérifier le statut
sudo docker compose ps
\`\`\`

## 📦 Services inclus

### 1. **Elasticsearch** (Port 9200)
- Moteur de recherche et base de données NoSQL
- Stocke tous les logs et métriques
- Cluster en mode single-node

### 2. **Kibana** (Port 5601)
- Interface web pour visualiser les données
- Dashboards pré-configurés
- Gestion de Fleet Server

### 3. **Logstash** (Ports 5044, 5000, 9600)
- Pipeline de traitement des données
- Reçoit les logs via Beats (port 5044)
- API de monitoring (port 9600)

### 4. **Filebeat**
- Collecte les logs système et applications
- Envoie vers Elasticsearch
- Surveillance des conteneurs Docker

### 5. **Metricbeat**
- Collecte les métriques système (CPU, RAM, disque)
- Surveillance Docker
- Métriques réseau

### 6. **Fleet Server** (Port 8220)
- Gestion centralisée des agents Elastic
- Déploiement de politiques
- Surveillance des agents

## 📊 Import de logs

### Via Kibana UI (Recommandé)
1. Ouvrir Kibana: http://localhost:5601
2. Aller dans **Menu** → **Management** → **Stack Management**
3. Cliquer sur **Data** → **Index Management**
4. Utiliser **Upload a file** ou **Create data view**

### Via Logstash TCP/UDP
\`\`\`bash
# Envoyer des logs via TCP
echo "Mon log de test" | nc localhost 5000

# Envoyer des logs via UDP
echo "Mon log UDP" | nc -u localhost 5000
\`\`\`

### Via Filebeat
Filebeat collecte automatiquement:
- \`/var/log/syslog\`
- \`/var/log/auth.log\`
- Logs des conteneurs Docker
- Logs Apache/Nginx

### Via API Elasticsearch
\`\`\`bash
curl -X POST "localhost:9200/mes-logs/_doc" \\
  -H 'Content-Type: application/json' \\
  -u elastic:changeme123 \\
  -d '{
    "timestamp": "'\$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "message": "Mon message de log",
    "level": "info",
    "source": "mon-app"
  }'
\`\`\`

## �� Sécurité

**⚠️ IMPORTANT**: Cette stack est configurée pour un environnement de **développement/formation**.

Pour la production:
- Changer le mot de passe dans [.env](.env)
- Activer SSL/TLS
- Configurer un firewall
- Utiliser des certificats valides

## 📁 Structure du projet

\`\`\`
.
├── docker-compose.yml          # Configuration des services
├── .env                        # Variables d'environnement
├── config/
│   ├── filebeat/
│   │   └── filebeat.yml       # Config collecte de logs
│   ├── logstash/
│   │   ├── config/
│   │   │   └── logstash.yml   # Config Logstash
│   │   └── pipeline/
│   │       └── logstash.conf  # Pipeline de traitement
│   └── metricbeat/
│       └── metricbeat.yml     # Config collecte de métriques
└── scripts/
    ├── start.sh               # Démarrage de la stack
    ├── stop.sh                # Arrêt de la stack
    └── reset.sh               # Réinitialisation complète
\`\`\`

## 🎯 Cas d'usage CDSA

Cette stack permet de:
- ✅ Centraliser les logs de plusieurs sources
- ✅ Analyser les événements de sécurité
- ✅ Surveiller les métriques système
- ✅ Créer des dashboards de monitoring
- ✅ Détecter des anomalies
- ✅ Corréler des événements
- ✅ Pratiquer l'analyse forensique

## 🐛 Dépannage

### Les conteneurs ne démarrent pas
\`\`\`bash
# Vérifier vm.max_map_count
sysctl vm.max_map_count  # Doit être >= 262144
sudo sysctl -w vm.max_map_count=262144

# Vérifier les logs
sudo docker compose logs elasticsearch
\`\`\`

### Pas de données dans Kibana
\`\`\`bash
# Vérifier que Filebeat/Metricbeat fonctionnent
sudo docker compose ps

# Vérifier les indices dans Elasticsearch
curl -u elastic:changeme123 http://localhost:9200/_cat/indices?v
\`\`\`

### Erreur de mémoire
- Augmenter la RAM allouée à Docker
- Réduire \`ES_JAVA_OPTS\` dans [.env](.env)
- Réduire \`LS_JAVA_OPTS\` dans [.env](.env)

## 📚 Documentation

- [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Logstash](https://www.elastic.co/guide/en/logstash/current/index.html)
- [Beats](https://www.elastic.co/guide/en/beats/libbeat/current/index.html)

## 🤝 Contribution

Les contributions sont les bienvenues! N'hésitez pas à ouvrir une issue ou une PR.

## �� Licence

MIT License - Libre d'utilisation pour l'apprentissage et la formation CDSA.

## ⚡ Stack testée et fonctionnelle

- ✅ Elasticsearch: Operational
- ✅ Kibana: Accessible sur port 5601
- ✅ Logstash: Pipeline actif
- ✅ Filebeat: Collecte logs système
- ✅ Metricbeat: Collecte métriques
- ✅ Fleet Server: Gestion d'agents

---

**Bon apprentissage pour la CDSA! 🎓**
