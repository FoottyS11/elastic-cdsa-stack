#!/bin/bash
# =============================================
# Script d'arrêt de la stack Elastic
# =============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🛑 Arrêt de la Stack Elastic..."
echo "================================"

cd "$PROJECT_DIR"

# Arrêt des conteneurs
docker-compose down

echo ""
echo "✅ Stack Elastic arrêtée."
echo ""
echo "💡 Pour supprimer aussi les données:"
echo "   docker-compose down -v"
echo ""
