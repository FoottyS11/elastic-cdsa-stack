FROM splunk/splunk:9.1.2

# Copier les configs forensiques dans l'image
COPY inputs.conf /tmp/splunk-defaults/inputs.conf
COPY props.conf /tmp/splunk-defaults/props.conf
COPY indexes.conf /tmp/splunk-defaults/indexes.conf
COPY entrypoint-wrapper.sh /tmp/entrypoint-wrapper.sh

USER root
RUN chmod +x /tmp/entrypoint-wrapper.sh && \
    mkdir -p /opt/splunk/etc/system/local && \
    cp /tmp/splunk-defaults/inputs.conf /opt/splunk/etc/system/local/ && \
    cp /tmp/splunk-defaults/props.conf /opt/splunk/etc/system/local/ && \
    cp /tmp/splunk-defaults/indexes.conf /opt/splunk/etc/system/local/ && \
    mkdir -p /opt/splunk-ingest/evtx /opt/splunk-ingest/json /opt/splunk-ingest/syslog && \
    chown -R 41812:41812 /opt/splunk/etc/system/local /opt/splunk-ingest
USER ansible

ENTRYPOINT ["/sbin/entrypoint.sh"]
CMD ["start-service"]
