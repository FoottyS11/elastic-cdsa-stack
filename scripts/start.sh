#!/bin/bash
# =============================================
# Script de démarrage de la stack Elastic
# =============================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🚀 Démarrage de la Stack Elastic pour CDSA..."
echo "=============================================="

# Vérification de Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

# Vérification du service Docker
if ! docker info &> /dev/null; then
    echo "❌ Le service Docker n'est pas démarré. Démarrage..."
    sudo systemctl start docker
fi

# Configuration vm.max_map_count pour Elasticsearch
echo "📝 Configuration du système pour Elasticsearch..."
sudo sysctl -w vm.max_map_count=262144 2>/dev/null || echo "⚠️  Impossible de configurer vm.max_map_count"

cd "$PROJECT_DIR"

# Démarrage de la stack
echo "🐳 Lancement des conteneurs Docker..."
docker-compose up -d

echo ""
echo "=============================================="
echo "✅ Stack Elastic démarrée avec succès!"
echo "=============================================="
echo ""
echo "📊 Accès aux services:"
echo "   - Kibana:        http://localhost:5601"
echo "   - Elasticsearch: http://localhost:9200"
echo "   - Logstash:      http://localhost:9600"
echo "   - Fleet Server:  http://localhost:8220"
echo ""
echo "🔐 Identifiants par défaut:"
echo "   - Utilisateur: elastic"
echo "   - Mot de passe: (voir fichier .env)"
echo ""
echo "📋 Commandes utiles:"
echo "   - Voir les logs:    docker-compose logs -f"
echo "   - Arrêter la stack: docker-compose down"
echo "   - Status:           docker-compose ps"
echo ""
