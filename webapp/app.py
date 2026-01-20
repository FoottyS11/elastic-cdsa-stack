#!/usr/bin/env python3
"""
Forensic File Uploader - Backend Flask
Plateforme d'upload automatique pour fichiers forensiques (Sherlock HTB)
"""

import os
import json
import socket
import zipfile
import tempfile
import shutil
import threading
import uuid
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

# Imports pour parsing des fichiers forensiques
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
    import xml.etree.ElementTree as ET
    EVTX_SUPPORT = True
except ImportError:
    EVTX_SUPPORT = False
    print("⚠️  Module python-evtx non disponible, support EVTX désactivé")

try:
    import pandas as pd
    CSV_SUPPORT = True
except ImportError:
    CSV_SUPPORT = False
    print("⚠️  Module pandas non disponible, support CSV désactivé")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB max
app.config['UPLOAD_FOLDER'] = '/app/uploads'

# Configuration Logstash
LOGSTASH_HOST = os.environ.get('LOGSTASH_HOST', 'logstash')
LOGSTASH_PORT = int(os.environ.get('LOGSTASH_PORT', 5000))

# Extensions de fichiers forensiques supportés
FORENSIC_EXTENSIONS = {
    '.evtx': 'Windows Event Log',
    '.json': 'JSON Log',
    '.csv': 'CSV Data',
    '.log': 'Text Log',
    '.txt': 'Text File',
}

# Extensions à ignorer
IGNORED_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.pdf', '.docx', '.doc', '.xlsx', '.xls',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.mp3', '.mp4',
    '.avi', '.mov', '.zip', '.rar', '.7z', '.tar', '.gz'
}

# Dictionnaire global pour stocker l'état des tâches
upload_tasks = {}

def xml_to_dict(element):
    """Convertit un élément XML en dictionnaire."""
    result = {}
    
    # Attributs
    for key, value in element.attrib.items():
        clean_key = key.split('}')[-1] if '}' in key else key
        result[clean_key] = value
    
    # Enfants
    for child in element:
        child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
        child_data = xml_to_dict(child)
        
        if child_tag in result:
            if not isinstance(result[child_tag], list):
                result[child_tag] = [result[child_tag]]
            result[child_tag].append(child_data)
        else:
            result[child_tag] = child_data
    
    # Texte direct
    if element.text and element.text.strip():
        text_content = element.text.strip()
        if not result:
            return text_content
        else:
            result['#text'] = text_content
            
    return result


def parse_evtx_file(file_path, source_name):
    """Parse un fichier EVTX et retourne une liste d'événements JSON."""
    events = []
    
    if not EVTX_SUPPORT:
        return events, "Module python-evtx non disponible"
    
    try:
        with Evtx(file_path) as evtx:
            for record in evtx.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    
                    event_dict = xml_to_dict(root)
                    event_dict['_source_file'] = source_name
                    event_dict['_parsed_at'] = datetime.utcnow().isoformat()
                    
                    events.append(event_dict)
                except Exception as e:
                    print(f"⚠️ Erreur parsing record: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
                    
    except Exception as e:
        return events, str(e)
    
    return events, None


def parse_json_file(file_path, source_name):
    """Parse un fichier JSON (une ligne = un événement ou JSON array)."""
    events = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().strip()
            
            # Essayer de parser comme JSON array
            if content.startswith('['):
                try:
                    data = json.loads(content)
                    for item in data:
                        if isinstance(item, dict):
                            item['_source_file'] = source_name
                            events.append(item)
                    return events, None
                except json.JSONDecodeError:
                    pass
            
            # Sinon, parser ligne par ligne (JSONL)
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if isinstance(event, dict):
                        event['_source_file'] = source_name
                        events.append(event)
                except json.JSONDecodeError:
                    continue
                    
    except Exception as e:
        return events, str(e)
    
    return events, None


def parse_csv_file(file_path, source_name):
    """Parse un fichier CSV et retourne une liste d'événements JSON."""
    events = []
    
    if not CSV_SUPPORT:
        return events, "Module pandas non disponible"
    
    try:
        df = pd.read_csv(file_path, encoding='utf-8', errors='ignore')
        for _, row in df.iterrows():
            event = row.to_dict()
            event['_source_file'] = source_name
            events.append(event)
    except Exception as e:
        return events, str(e)
    
    return events, None


def parse_log_file(file_path, source_name):
    """Parse un fichier log texte ligne par ligne."""
    events = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                events.append({
                    'message': line,
                    'line_number': i,
                    '_source_file': source_name
                })
    except Exception as e:
        return events, str(e)
    
    return events, None


def send_to_logstash(events, index_name):
    """Envoie les événements vers Logstash via TCP."""
    if not events:
        return 0, "Aucun événement à envoyer"
    
    sent_count = 0
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((LOGSTASH_HOST, LOGSTASH_PORT))
        
        for event in events:
            # Ajouter l'index name pour le routage dans Logstash
            event['_index_hint'] = index_name
            
            try:
                data = json.dumps(event, default=str) + '\n'
                sock.sendall(data.encode('utf-8'))
                sent_count += 1
            except Exception:
                continue
        
        sock.close()
        
    except Exception as e:
        return sent_count, str(e)
    
    return sent_count, None


def process_file(file_path, source_name, index_name):
    """Traite un fichier forensique selon son type."""
    ext = Path(file_path).suffix.lower()
    
    if ext == '.evtx':
        events, error = parse_evtx_file(file_path, source_name)
    elif ext == '.json':
        events, error = parse_json_file(file_path, source_name)
    elif ext == '.csv':
        events, error = parse_csv_file(file_path, source_name)
    elif ext in ['.log', '.txt']:
        events, error = parse_log_file(file_path, source_name)
    else:
        return 0, f"Type de fichier non supporté: {ext}"
    
    if error:
        return 0, error
    
    if not events:
        return 0, "Aucun événement extrait"
    
    sent, send_error = send_to_logstash(events, index_name)
    
    if send_error:
        return sent, send_error
    
    return sent, None


def scan_directory(directory):
    """Scanne un répertoire et retourne les fichiers forensiques."""
    forensic_files = []
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            ext = Path(filename).suffix.lower()
            
            if ext in IGNORED_EXTENSIONS:
                continue
            
            if ext in FORENSIC_EXTENSIONS:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, directory)
                forensic_files.append({
                    'path': full_path,
                    'name': filename,
                    'relative_path': rel_path,
                    'type': FORENSIC_EXTENSIONS.get(ext, 'Unknown'),
                    'extension': ext,
                    'size': os.path.getsize(full_path)
                })
    
    return forensic_files


def create_kibana_data_view(index_name):
    """Crée un Data View dans Kibana pour l'index."""
    import urllib.request
    import urllib.error
    
    kibana_url = "http://kibana:5601/api/data_views/data_view"
    
    data = {
        "data_view": {
            "title": f"{index_name}*",
            "name": index_name,
            "id": index_name,
            "timeFieldName": "@timestamp"
        }
    }
    
    try:
        req = urllib.request.Request(
            kibana_url,
            data=json.dumps(data).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'kbn-xsrf': 'true'
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            print(f"✅ Data View '{index_name}' créé dans Kibana")
            return True
            
    except urllib.error.HTTPError as e:
        if e.code == 409:
            print(f"ℹ️  Data View '{index_name}' existe déjà")
            return True
        print(f"⚠️  Impossible de créer le Data View: {e}")
        return False
    except Exception as e:
        print(f"⚠️  Erreur Kibana: {e}")
        return False


def process_upload_background(task_id, file_path, password, extract_dir, index_name):
    """Fonction de traitement en arrière-plan."""
    try:
        upload_tasks[task_id]['status'] = 'extracting'
        
        # 1. Extraction du ZIP
        scan_dir = extract_dir
        
        if file_path.endswith('.zip'):
             with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Vérifier si mot de passe requis
                try:
                    zip_ref.testzip()
                except RuntimeError as e:
                    if 'encrypted' in str(e) and not password:
                        upload_tasks[task_id] = {
                            'status': 'error', 
                            'error': 'Ce ZIP est protégé par mot de passe.', 
                            'password_required': True
                        }
                        return
                        
                # Extraction
                try:
                    zip_ref.extractall(extract_dir, pwd=password.encode('utf-8') if password else None)
                except RuntimeError as e:
                    if 'Bad password' in str(e):
                        upload_tasks[task_id] = {
                            'status': 'error', 
                            'error': 'Mot de passe incorrect.', 
                            'password_required': True
                        }
                        return
                    raise e
                
             scan_dir = extract_dir
        else:
             # Si ce n'est pas un ZIP (mais accepté par upload_file), le dossier est déjà prêt
             pass

        # 2. Scan des fichiers
        upload_tasks[task_id]['status'] = 'scanning'
        forensic_files = scan_directory(scan_dir)

        upload_tasks[task_id]['total'] = len(forensic_files)
        upload_tasks[task_id]['status'] = 'processing'
        
        # 3. Traitement des fichiers
        results = []
        total_events = 0
        
        for i, ffile in enumerate(forensic_files):
            # Mise à jour de la progression
            upload_tasks[task_id]['current'] = i + 1
            upload_tasks[task_id]['current_file'] = ffile['relative_path']
            print(f"📄 [{i+1}/{len(forensic_files)}] Traitement: {ffile['relative_path']}")
            
            sent, error = process_file(
                ffile['path'], 
                ffile['relative_path'],
                index_name
            )
            
            report = {
                'file': ffile['relative_path'],
                'type': ffile['type'],
                'size': ffile['size'],
                'events_sent': sent,
                'error': error,
                'status': 'success' if error is None else 'error'
            }
            results.append(report)
            
            # Mise à jour partielle du résultat si on veut permettre un suivi temps réel des fichiers
            upload_tasks[task_id]['last_result'] = report
            
            total_events += sent
        
        # 4. Création Data View
        data_view_created = create_kibana_data_view(index_name)
        
        # Compter les fichiers réussis
        successful_files = sum(1 for r in results if r['status'] == 'success')
        
        # Résultat final
        upload_tasks[task_id]['result'] = {
            'success': True,
            'message': f'Import terminé! {total_events} événements importés depuis {successful_files} fichiers.',
            'index_name': index_name,
            'files_found': len(forensic_files),
            'files_processed': successful_files,
            'files_failed': len(results) - successful_files,
            'total_events': total_events,
            'data_view_created': data_view_created,
            'details': results,
            'kibana_url': f'http://localhost:5601/app/discover#/?_g=()&_a=(dataSource:(dataViewId:\'{index_name}\',type:dataView))'
        }
        upload_tasks[task_id]['status'] = 'completed'
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        upload_tasks[task_id] = {'status': 'error', 'error': str(e)}
             
    finally:
        # Nettoyage différé
        def clean_temp():
            time.sleep(300) # Garder 5 min pour être sûr
            try:
                shutil.rmtree(extract_dir, ignore_errors=True)
            except:
                pass
            # Ne pas supprimer tout de suite de upload_tasks pour que le client puisse lire le résultat
            
        threading.Thread(target=clean_temp, daemon=True).start()


@app.route('/')
def index():
    """Page principale avec l'interface d'upload."""
    return render_template('index.html', 
                         evtx_support=EVTX_SUPPORT,
                         csv_support=CSV_SUPPORT)


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """API d'upload de fichier ZIP."""
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier fourni'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné'}), 400
        
    password = request.form.get('password', None)
    
    # Créer ID de tâche
    task_id = str(uuid.uuid4())
    
    filename = secure_filename(file.filename)
    file_ext = os.path.splitext(filename)[1].lower()
    
    # Nom de l'index
    safe_name = Path(filename).stem.lower().replace(' ', '_').replace('.', '_')
    index_name = f"sherlock-{safe_name}-{datetime.now().strftime('%Y.%m.%d')}"
    
    # Créer dossier temporaire pour cette tâche
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    extract_dir = os.path.join(tempfile.gettempdir(), f"forensic_{timestamp}_{task_id}")
    os.makedirs(extract_dir, exist_ok=True)
    
    if file_ext == '.zip' or file_ext in FORENSIC_EXTENSIONS:
        try:
            # Sauvegarder fichier
            save_path = os.path.join(extract_dir, filename)
            file.save(save_path)
            
            # Initialiser tâche
            upload_tasks[task_id] = {
                'status': 'starting',
                'total': 0,
                'current': 0,
                'current_file': 'Démarrage...'
            }
            
            # Démarrer thread
            thread = threading.Thread(
                target=process_upload_background,
                args=(task_id, save_path, password, extract_dir, index_name)
            )
            thread.daemon = True
            thread.start()
            
            return jsonify({'task_id': task_id, 'status': 'started'}), 202
            
        except Exception as e:
            shutil.rmtree(extract_dir, ignore_errors=True)
            return jsonify({'error': str(e)}), 500
            
    else:
        shutil.rmtree(extract_dir, ignore_errors=True)
        return jsonify({'error': 'Type de fichier non supporté'}), 400


@app.route('/api/task/<task_id>', methods=['GET'])
def get_task_status(task_id):
    task = upload_tasks.get(task_id)
    if not task:
        return jsonify({'error': 'Tâche non trouvée'}), 404
        
    return jsonify(task)


@app.route('/api/status', methods=['GET'])
def status():
    """Vérifie le statut des services."""
    status_info = {
        'webapp': 'ok',
        'evtx_support': EVTX_SUPPORT,
        'csv_support': CSV_SUPPORT,
        'logstash': 'unknown'
    }
    
    # Tester la connexion à Logstash
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((LOGSTASH_HOST, LOGSTASH_PORT))
        sock.close()
        status_info['logstash'] = 'ok' if result == 0 else 'error'
    except Exception:
        status_info['logstash'] = 'error'
    
    return jsonify(status_info)


if __name__ == '__main__':
    # Créer le dossier d'upload s'il n'existe pas
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Lancer le serveur (threaded=True est par défaut)
    app.run(host='0.0.0.0', port=8080, debug=True)
