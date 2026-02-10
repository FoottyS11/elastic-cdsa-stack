#!/bin/bash
# Wrapper entrypoint: copie les configs forensiques puis lance Splunk normalement

CONFIG_DIR="/opt/splunk/etc/system/local"

# Attendre que le dossier existe (créé par l'entrypoint Splunk)
# On copie dès maintenant, Splunk les prendra au démarrage
mkdir -p "$CONFIG_DIR"

# Copier les configs personnalisées
cp -f /tmp/splunk-defaults/inputs.conf "$CONFIG_DIR/inputs.conf" 2>/dev/null || true
cp -f /tmp/splunk-defaults/props.conf "$CONFIG_DIR/props.conf" 2>/dev/null || true
cp -f /tmp/splunk-defaults/indexes.conf "$CONFIG_DIR/indexes.conf" 2>/dev/null || true

echo "✅ Configs forensiques copiées dans $CONFIG_DIR"

# Créer les dossiers d'ingestion
mkdir -p /opt/splunk-ingest/evtx /opt/splunk-ingest/json /opt/splunk-ingest/syslog

# Lancer l'entrypoint Splunk original
exec /sbin/entrypoint.sh "$@"
