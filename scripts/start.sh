#!/bin/bash
set -e

echo "🚀 Démarrage de la Stack CDSA + Forensic Uploader..."
echo "========================================================"

sudo sysctl -w vm.max_map_count=262144 2>/dev/null || true

echo "🐳 Build et lancement des services..."
docker-compose up -d --build

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
echo "⏳ Attente du Forensic Uploader..."

for i in {1..30}; do
    if curl -s http://localhost:8080/api/status 2>/dev/null | grep -q 'webapp'; then
        echo ""
        echo "✅ Forensic Uploader est prêt !"
        break
    fi
    printf "\r   ⏱️  %d/30 secondes..." $i
    sleep 1
done

echo ""
echo "========================================================"
echo "📊 Accès aux services :"
echo "   - 📤 Forensic Uploader : http://localhost:8080"
echo "   - 📊 Kibana            : http://localhost:5601"
echo "   - 🔍 Elasticsearch     : http://localhost:9200"
echo ""
echo "💡 Utilisation :"
echo "   1. Ouvrir http://localhost:8080"
echo "   2. Glisser-déposer un ZIP de Sherlock"
echo "   3. Consulter les logs dans Kibana"
echo "========================================================"
