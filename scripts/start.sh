#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARDS_DIR="$SCRIPT_DIR/../dashboards"

echo "🚀 Démarrage de la Stack CDSA + Forensic Uploader..."
echo "========================================================"

sudo sysctl -w vm.max_map_count=262144 2>/dev/null || true

echo "🐳 Build et lancement des services..."
docker-compose up -d --build

echo ""
echo "⏳ Attente de Kibana..."

KIBANA_READY=false
for i in {1..60}; do
    if curl -s http://localhost:5601/api/status 2>/dev/null | grep -q 'available'; then
        echo ""
        echo "✅ Kibana est prêt !"
        KIBANA_READY=true
        break
    fi
    printf "\r   ⏱️  %d/60 secondes..." $i
    sleep 1
done

# Attente de Splunk
echo ""
echo "⏳ Attente de Splunk..."

SPLUNK_READY=false
for i in {1..90}; do
    if curl -s http://localhost:8000/en-US/account/login 2>/dev/null | grep -q 'Splunk'; then
        echo ""
        echo "✅ Splunk est prêt !"
        SPLUNK_READY=true
        break
    fi
    printf "\r   ⏱️  %d/90 secondes..." $i
    sleep 1
done

if [ "$SPLUNK_READY" = false ]; then
    echo ""
    echo "⚠️  Splunk n'est pas encore prêt (peut prendre jusqu'à 3 min au premier démarrage)"
fi

# Import des dashboards SIEM si Kibana est prêt
if [ "$KIBANA_READY" = true ] && [ -d "$DASHBOARDS_DIR" ]; then
    echo ""
    echo "📊 Import des dashboards SIEM..."
    
    for file in "$DASHBOARDS_DIR"/*.ndjson; do
        if [ -f "$file" ]; then
            basename=$(basename "$file" .ndjson)
            response=$(curl -s -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
                -H "kbn-xsrf: true" \
                --form file=@"$file" 2>&1)
            
            if echo "$response" | grep -q '"success":true\|"successCount"'; then
                echo "   ✅ $basename"
            else
                echo "   ⚠️ $basename (erreur)"
            fi
        fi
    done
    echo "✅ Dashboards SIEM importés !"
fi

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
echo "   - 🟢 Splunk            : http://localhost:8000"
echo ""
echo "📈 Dashboards SIEM disponibles :"
echo "   - 🔐 Windows Security"
echo "   - 🔄 Lateral Movement"
echo "   - 🔒 Persistence Mechanisms"
echo "   - 💻 PowerShell Analysis"
echo ""
echo "🟢 Splunk :"
echo "   - User: admin / Password: voir .env (SPLUNK_PASSWORD)"
echo "   - HEC Token: voir .env (SPLUNK_HEC_TOKEN)"
echo "   - Index forensic: forensic_evtx"
echo ""
echo "💡 Utilisation :"
echo "   1. Ouvrir http://localhost:8080"
echo "   2. Glisser-déposer un ZIP de Sherlock ou un .mem"
echo "   3. Les logs sont envoyés vers Elastic ET Splunk"
echo "   4. Consulter dans Kibana OU Splunk"
echo "========================================================"
