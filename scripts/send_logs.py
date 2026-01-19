#!/usr/bin/env python3
import socket
import json
import sys
import argparse

def send_json_to_logstash(file_path, host='localhost', port=5000):
    print(f"🚀 Lecture du fichier : {file_path}")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        print(f"✅ Connecté à Logstash sur {host}:{port}")
    except Exception as e:
        print(f"❌ Erreur de connexion : {e}")
        return

    count = 0
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    # Vérifions si c'est du JSON valide
                    json.loads(line)
                    s.sendall(line.encode('utf-8') + b'\n')
                    count += 1
                    if count % 100 == 0:
                        print(f"   -> {count} événements envoyés...", end='\r')
                except json.JSONDecodeError:
                    print(f"⚠️  Ligne ignorée (pas du JSON valide)")
    except Exception as e:
        print(f"❌ Erreur de lecture : {e}")
    finally:
        s.close()
        print(f"\n✅ Terminé! {count} événements envoyés à Logstash.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Envoi de logs JSON vers Logstash')
    parser.add_argument('file', help='Fichier contenant des logs JSON (une ligne par log)')
    args = parser.parse_args()
    
    send_json_to_logstash(args.file)
