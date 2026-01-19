#!/bin/bash
set -e

echo "🚀 Démarrage de la Stack CDSA (Mode Sans Sécurité)..."
echo "======================================================"

sudo sysctl -w vm.max_map_count=262144 2>/dev/null || true

echo "🐳 Lancement des services..."
docker-compose up -d

echo ""
echo "⏳ Attente de Kibana..."

for i in {1..60}; do
    if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q 'available'; then
        echo ""
        echo "✅ Kibana est prêt !"
        break
    fi
    printf "\r   ⏱️  %d/60 secondes..." $i
    sleep 1
done

echo ""
echo "======================================================"
echo "📊 Accès aux services (SANS AUTHENTIFICATION) :"
echo "   - Kibana : http://localhost:5601"
echo "   - ES     : http://localhost:9200"
echo ""
echo "📥 Ingestion EVTX :"
echo "   python3 scripts/send_logs.py <votre_fichier.json>"
echo "======================================================"
