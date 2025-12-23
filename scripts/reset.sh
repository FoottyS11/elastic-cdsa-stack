#!/bin/bash
# =============================================
# Script de réinitialisation complète
# =============================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "⚠️  ATTENTION: Ce script va supprimer toutes les données!"
echo "=============================================="
read -p "Êtes-vous sûr? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Annulé."
    exit 0
fi

cd "$PROJECT_DIR"

echo "🗑️  Arrêt et suppression des conteneurs et volumes..."
docker-compose down -v --remove-orphans

echo "🧹 Nettoyage des images orphelines..."
docker system prune -f

echo ""
echo "✅ Réinitialisation terminée."
echo "   Lancez './scripts/start.sh' pour redémarrer."
echo ""
