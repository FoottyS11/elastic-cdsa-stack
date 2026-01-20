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
import queue
import concurrent.futures

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

# Import Volatility3 pour analyse mémoire
try:
    from volatility3.framework import contexts, constants, automagic, plugins
    from volatility3.framework.configuration import requirements
    from volatility3 import framework
    from volatility3.plugins.windows import pslist, netscan, cmdline, pstree
    VOLATILITY_SUPPORT = True
    print("✅ Module volatility3 chargé, support Memory Dump activé")
except ImportError as e:
    VOLATILITY_SUPPORT = False
    print(f"⚠️  Module volatility3 non disponible: {e}")

# Import Prefetch parser
try:
    from prefetch_parser import prefetch2json
    PREFETCH_SUPPORT = True
    print("✅ Module prefetch-parser chargé, support Prefetch activé")
except ImportError as e:
    PREFETCH_SUPPORT = False
    print(f"⚠️  Module prefetch-parser non disponible: {e}")

# Import Registry parser (regipy)
try:
    from regipy.registry import RegistryHive
    from regipy.plugins.utils import run_relevant_plugins
    REGISTRY_SUPPORT = True
    print("✅ Module regipy chargé, support Registry activé")
except ImportError as e:
    REGISTRY_SUPPORT = False
    print(f"⚠️  Module regipy non disponible: {e}")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2 GB max
app.config['UPLOAD_FOLDER'] = '/app/uploads'

# Gestionnaire d'erreur pour fichiers trop volumineux
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'error': 'Fichier trop volumineux. Limite: 2 GB',
        'max_size_mb': 2048
    }), 413

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
    '.mem': 'Memory Dump',
    '.raw': 'Memory Dump (RAW)',
    '.vmem': 'VMware Memory',
    '.dmp': 'Windows Crash Dump',
    '.pf': 'Windows Prefetch',
}

# Noms de fichiers Registry reconnus (sans extension)
REGISTRY_FILENAMES = {
    'system', 'software', 'sam', 'security', 'ntuser.dat', 'usrclass.dat',
    'amcache.hve', 'default', 'components'
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
    """Parse un fichier EVTX et yield des événements JSON."""
    if not EVTX_SUPPORT:
        return [], "Module python-evtx non disponible"
    
    def generator():
        try:
            with Evtx(file_path) as evtx:
                for record in evtx.records():
                    try:
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        
                        event_dict = xml_to_dict(root)
                        event_dict['_source_file'] = source_name
                        event_dict['_parsed_at'] = datetime.utcnow().isoformat()
                        
                        yield event_dict
                    except Exception as e:
                        print(f"⚠️ Erreur parsing record dans {source_name}: {e}")
                        continue
        except Exception as e:
            print(f"❌ Erreur critique lecture EVTX {source_name}: {e}")
            raise e

    return generator(), None


def parse_json_file(file_path, source_name):
    """Parse un fichier JSON (une ligne = un événement ou JSON array) en streaming."""
    def generator():
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Lecture intelligente: on regarde le premier caractère
                first_char = f.read(1)
                f.seek(0)
                
                if first_char == '[':
                    # C'est un array JSON, on est obligé de charger (ou utiliser un parser stream, mais standard json load est simple)
                    # Pour éviter de tout charger si c'est énorme, on pourrait utiliser 'ijson' mais pas dispo ici.
                    # On fallback sur load standard pour l'instant pour les arrays.
                    data = json.load(f)
                    for item in data:
                        if isinstance(item, dict):
                            item['_source_file'] = source_name
                            yield item
                else:
                    # JSONL (Line Delimited) - Vrai streaming
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        try:
                            event = json.loads(line)
                            if isinstance(event, dict):
                                event['_source_file'] = source_name
                                yield event
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"❌ Erreur lecture JSON {source_name}: {e}")
            raise e

    return generator(), None


def parse_csv_file(file_path, source_name):
    """Parse un fichier CSV et yield des événements JSON."""
    if not CSV_SUPPORT:
        return [], "Module pandas non disponible"
    
    def generator():
        try:
            # Chunksize permet de lire le CSV par morceaux sans charger tout en RAM
            for chunk in pd.read_csv(file_path, encoding='utf-8', errors='ignore', chunksize=1000):
                for _, row in chunk.iterrows():
                    event = row.to_dict()
                    event['_source_file'] = source_name
                    yield event
        except Exception as e:
            print(f"❌ Erreur lecture CSV {source_name}: {e}")
            raise e
            
    return generator(), None


def parse_log_file(file_path, source_name):
    """Parse un fichier log texte ligne par ligne en streaming."""
    def generator():
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: continue
                    yield {
                        'message': line,
                        'line_number': i,
                        '_source_file': source_name
                    }
        except Exception as e:
            print(f"❌ Erreur lecture Log {source_name}: {e}")
            raise e

    return generator(), None


def parse_memory_file(file_path, source_name):
    """
    Analyse un dump mémoire avec Volatility3.
    Exécute plusieurs plugins et yield les résultats comme events.
    """
    if not VOLATILITY_SUPPORT:
        return [], "Module volatility3 non disponible"
    
    def generator():
        try:
            print(f"🧠 Démarrage analyse mémoire: {source_name}")
            
            # Configuration Volatility3
            framework.require_interface_version(2, 0, 0)
            ctx = contexts.Context()
            
            # Configurer le fichier source
            single_location = "file://" + os.path.abspath(file_path)
            ctx.config['automagic.LayerStacker.single_location'] = single_location
            
            # Automagics pour détecter automatiquement l'OS
            available_automagics = automagic.available(ctx)
            automagics_list = automagic.choose_automagic(available_automagics, pslist.PsList)
            
            # Plugins à exécuter avec leurs configurations
            plugins_config = [
                {
                    'name': 'pslist',
                    'plugin': pslist.PsList,
                    'event_type': 'memory.process',
                    'fields': ['PID', 'PPID', 'ImageFileName', 'CreateTime', 'ExitTime', 
                              'Threads', 'Handles', 'SessionId', 'Wow64', 'Offset']
                },
                {
                    'name': 'netscan',
                    'plugin': netscan.NetScan,
                    'event_type': 'memory.network',
                    'fields': ['Offset', 'Proto', 'LocalAddr', 'LocalPort', 
                              'ForeignAddr', 'ForeignPort', 'State', 'PID', 'Owner', 'Created']
                },
                {
                    'name': 'cmdline',
                    'plugin': cmdline.CmdLine,
                    'event_type': 'memory.commandline',
                    'fields': ['PID', 'Process', 'Args']
                }
            ]
            
            for plugin_cfg in plugins_config:
                plugin_name = plugin_cfg['name']
                plugin_class = plugin_cfg['plugin']
                event_type = plugin_cfg['event_type']
                expected_fields = plugin_cfg['fields']
                
                try:
                    print(f"  → Exécution plugin: {plugin_name}")
                    
                    # Construire le plugin
                    constructed = plugins.construct_plugin(
                        ctx, 
                        automagics_list, 
                        plugin_class, 
                        "plugins", 
                        None, 
                        None
                    )
                    
                    if constructed is None:
                        print(f"  ⚠️ Plugin {plugin_name} non construit (OS non compatible?)")
                        continue
                    
                    # Exécuter et récupérer les résultats
                    treegrid = constructed.run()
                    
                    for row in treegrid.populate():
                        # row est un tuple (depth, row_values)
                        if len(row) < 2:
                            continue
                            
                        row_values = row[1]
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            '_source_file': source_name,
                            'volatility.plugin': plugin_name,
                            'event.type': event_type
                        }
                        
                        # Mapper les colonnes
                        for i, field_name in enumerate(expected_fields):
                            if i < len(row_values):
                                value = row_values[i]
                                # Convertir en type sérialisable
                                if hasattr(value, 'isoformat'):
                                    value = value.isoformat()
                                elif hasattr(value, '__str__'):
                                    value = str(value)
                                event[f'volatility.{field_name.lower()}'] = value
                        
                        yield event
                        
                except Exception as plugin_error:
                    print(f"  ⚠️ Erreur plugin {plugin_name}: {plugin_error}")
                    # Yield un événement d'erreur pour traçabilité
                    yield {
                        '@timestamp': datetime.utcnow().isoformat(),
                        '_source_file': source_name,
                        'volatility.plugin': plugin_name,
                        'event.type': 'memory.error',
                        'error.message': str(plugin_error)
                    }
                    continue
                    
            print(f"✅ Analyse mémoire terminée: {source_name}")
            
        except Exception as e:
            print(f"❌ Erreur critique analyse mémoire {source_name}: {e}")
            import traceback
            traceback.print_exc()
            raise e
    
    return generator(), None


def parse_prefetch_file(file_path, source_name):
    """
    Parse un fichier Windows Prefetch (.pf).
    Extrait les informations d'exécution des applications.
    """
    if not PREFETCH_SUPPORT:
        return [], "Module prefetch-parser non disponible"
    
    def generator():
        try:
            print(f"📋 Parsing Prefetch: {source_name}")
            # prefetch2json retourne un dictionnaire complet
            data = prefetch2json(file_path)
            
            # Événement principal
            event = {
                '@timestamp': datetime.utcnow().isoformat(),
                '_source_file': source_name,
                'event.type': 'prefetch.execution',
            }
            
            # Mapper dynamiquement les champs
            if isinstance(data, dict):
                for key, value in data.items():
                    # Nettoyage des clés et valeurs
                    clean_key = key.lower().replace(' ', '_')
                    
                    # Traitement spécial pour les listes (fichiers, etc.)
                    if isinstance(value, list) and len(value) > 100:
                         # Échantillon pour ne pas saturer
                         event[f'prefetch.{clean_key}_count'] = len(value)
                         event[f'prefetch.{clean_key}_sample'] = value[:50]
                    else:
                        event[f'prefetch.{clean_key}'] = value
                        
            yield event
            exe_name = data.get('Executable Name', 'Unknown')
            run_count = data.get('Run Count', 0)
            print(f"✅ Prefetch parsé: {exe_name} (run count: {run_count})")
            
        except Exception as e:
            print(f"❌ Erreur parsing Prefetch {source_name}: {e}")
            yield {
                '@timestamp': datetime.utcnow().isoformat(),
                '_source_file': source_name,
                'event.type': 'prefetch.error',
                'error.message': str(e)
            }
    
    return generator(), None


def parse_registry_file(file_path, source_name):
    """
    Parse un fichier Registry Windows (SYSTEM, SOFTWARE, NTUSER.DAT, etc.)
    utilisant regipy et ses plugins forensiques.
    """
    if not REGISTRY_SUPPORT:
        return [], "Module regipy non disponible"
    
    def generator():
        try:
            print(f"🔑 Parsing Registry: {source_name}")
            
            # Ouvrir le hive
            reg = RegistryHive(file_path)
            
            # Informations de base sur le hive
            yield {
                '@timestamp': datetime.utcnow().isoformat(),
                '_source_file': source_name,
                'event.type': 'registry.hive_info',
                'registry.hive_type': reg.hive_type if hasattr(reg, 'hive_type') else 'unknown',
                'registry.root_key': str(reg.root) if hasattr(reg, 'root') else None,
            }
            
            # Exécuter les plugins forensiques pertinents
            try:
                plugins_output = run_relevant_plugins(reg, as_json=True)
                
                for plugin_name, plugin_data in plugins_output.items():
                    if isinstance(plugin_data, list):
                        for entry in plugin_data:
                            event = {
                                '@timestamp': datetime.utcnow().isoformat(),
                                '_source_file': source_name,
                                'event.type': f'registry.{plugin_name.lower()}',
                                'registry.plugin': plugin_name,
                            }
                            # Ajouter les données du plugin
                            if isinstance(entry, dict):
                                for k, v in entry.items():
                                    # Nettoyer les valeurs
                                    if v is not None:
                                        event[f'registry.{k}'] = str(v) if not isinstance(v, (str, int, float, bool)) else v
                            else:
                                event['registry.value'] = str(entry)
                            yield event
                    elif isinstance(plugin_data, dict):
                        event = {
                            '@timestamp': datetime.utcnow().isoformat(),
                            '_source_file': source_name,
                            'event.type': f'registry.{plugin_name.lower()}',
                            'registry.plugin': plugin_name,
                        }
                        for k, v in plugin_data.items():
                            if v is not None:
                                event[f'registry.{k}'] = str(v) if not isinstance(v, (str, int, float, bool)) else v
                        yield event
                        
                print(f"✅ Registry parsé avec {len(plugins_output)} plugins")
                
            except Exception as plugin_error:
                print(f"⚠️ Erreur plugins registry: {plugin_error}")
                # Fallback: parcourir les clés manuellement
                yield {
                    '@timestamp': datetime.utcnow().isoformat(),
                    '_source_file': source_name,
                    'event.type': 'registry.plugin_error',
                    'error.message': str(plugin_error)
                }
            
        except Exception as e:
            print(f"❌ Erreur parsing Registry {source_name}: {e}")
            import traceback
            traceback.print_exc()
            yield {
                '@timestamp': datetime.utcnow().isoformat(),
                '_source_file': source_name,
                'event.type': 'registry.error',
                'error.message': str(e)
            }
    
    return generator(), None


class LogstashSender:
    """Gère l'envoi asynchrone vers Logstash via une Queue."""
    def __init__(self, host, port, index_name):
        self.host = host
        self.port = port
        self.index_name = index_name
        self.queue = queue.Queue(maxsize=10000) # Backpressure pour ne pas saturer la RAM
        self.running = True
        self.total_sent = 0
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.sock = None
        
    def start(self):
        self.thread.start()
        
    def stop(self):
        self.running = False
        self.queue.put(None) # Sentinel
        self.thread.join()
        if self.sock:
            self.sock.close()
            
    def enqueue(self, event):
        self.queue.put(event)
        
    def _connect(self):
        try:
            if self.sock: self.sock.close()
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"❌ Erreur connexion Logstash: {e}")
            return False

    def _run_loop(self):
        batch = []
        last_send = time.time()
        
        while self.running or not self.queue.empty():
            try:
                # Récupérer item avec timeout pour flusher périodiquement
                try:
                    item = self.queue.get(timeout=1.0)
                except queue.Empty:
                    item = None
                
                if item is None:
                    # Sentinel ou timeout -> flush si besoin
                    if batch and (time.time() - last_send > 1.0 or not self.running):
                        self._send_batch(batch)
                        batch = []
                        last_send = time.time()
                    continue
                    
                # Minification
                data = json.dumps(item, default=str, separators=(',', ':'))
                # Ajout index hint
                # Note: On pourrait l'injecter ici ou avant.
                # L'item est déjà un dict
                if '_index_hint' not in item:
                     item['_index_hint'] = self.index_name  # Fallback si pas mis avant
                     
                batch.append(data)
                
                if len(batch) >= 500:
                    self._send_batch(batch)
                    batch = []
                    last_send = time.time()
                    
            except Exception as e:
                print(f"⚠️ Erreur thread sender: {e}")
                
    def _send_batch(self, batch):
        if not batch: return
        
        payload = '\n'.join(batch) + '\n'
        data = payload.encode('utf-8')
        
        # Tentative d'envoi avec reconnexion simple
        for retry in range(3):
            try:
                if not self.sock:
                    if not self._connect():
                        time.sleep(1)
                        continue
                
                self.sock.sendall(data)
                with self.lock:
                    self.total_sent += len(batch)
                return
            except Exception:
                self.sock = None # Force reconnexion
                time.sleep(1)
        
        print(f"❌ Echec envoi de {len(batch)} logs après retries")


def process_file_worker(file_info, sender, index_name):
    """Worker pour traiter un fichier et mettre les résultats dans la queue."""
    file_path = file_info['path']
    relative_path = file_info['relative_path']
    ext = file_info['extension']
    
    events_count = 0
    error = None
    
    try:
        generator = None
        gen_error = None
        
        if ext == '.evtx':
            generator, gen_error = parse_evtx_file(file_path, relative_path)
        elif ext == '.json':
            generator, gen_error = parse_json_file(file_path, relative_path)
        elif ext == '.csv':
            generator, gen_error = parse_csv_file(file_path, relative_path)
        elif ext in ['.log', '.txt']:
            generator, gen_error = parse_log_file(file_path, relative_path)
        elif ext in ['.mem', '.raw', '.vmem', '.dmp']:
            generator, gen_error = parse_memory_file(file_path, relative_path)
        elif ext == '.pf':
            generator, gen_error = parse_prefetch_file(file_path, relative_path)
        elif ext == '.reg':
            generator, gen_error = parse_registry_file(file_path, relative_path)
        else:
            return 0, "Type non supporté"
            
        if gen_error:
            return 0, gen_error
            
        for event in generator:
            event['_index_hint'] = index_name
            sender.enqueue(event)
            events_count += 1
            
    except Exception as e:
        error = str(e)
        
    return events_count, error


def scan_directory(directory):
    """Scanne un répertoire et retourne les fichiers forensiques."""
    forensic_files = []
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            ext = Path(filename).suffix.lower()
            filename_lower = filename.lower()
            
            if ext in IGNORED_EXTENSIONS:
                continue
            
            # Vérifier si c'est un fichier Registry par son nom
            is_registry = filename_lower in REGISTRY_FILENAMES
            
            if ext in FORENSIC_EXTENSIONS or is_registry:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, directory)
                
                if is_registry:
                    file_type = 'Windows Registry'
                    file_ext = '.reg'  # Extension virtuelle pour le traitement
                else:
                    file_type = FORENSIC_EXTENSIONS.get(ext, 'Unknown')
                    file_ext = ext
                
                forensic_files.append({
                    'path': full_path,
                    'name': filename,
                    'relative_path': rel_path,
                    'type': file_type,
                    'extension': file_ext,
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
    """Traitement background optimisé (Multi-thread + Queue)."""
    sender = None
    print(f"🚀 Démarrage traitement background: task_id={task_id}")
    print(f"   file_path={file_path}")
    print(f"   extract_dir={extract_dir}")
    try:
        upload_tasks[task_id]['status'] = 'extracting'
        print(f"   Statut mis à extracting")
        
        # 1. Extraction (inchangé)
        scan_dir = extract_dir
        if file_path.endswith('.zip'):
             with zipfile.ZipFile(file_path, 'r') as zip_ref:
                try:
                    zip_ref.testzip()
                except RuntimeError as e:
                    if 'encrypted' in str(e) and not password:
                        upload_tasks[task_id].update({'status': 'error', 'error': 'Zip chiffré', 'password_required': True})
                        return
                try:
                    zip_ref.extractall(extract_dir, pwd=password.encode('utf-8') if password else None)
                except RuntimeError as e:
                    if 'Bad password' in str(e):
                        upload_tasks[task_id].update({'status': 'error', 'error': 'Mot de passe incorrect', 'password_required': True})
                        return
                    raise e
             scan_dir = extract_dir

        # 2. Scan
        upload_tasks[task_id]['status'] = 'scanning'
        forensic_files = scan_directory(scan_dir)
        upload_tasks[task_id]['total'] = len(forensic_files)
        
        # 3. Traitement Parallèle
        upload_tasks[task_id]['status'] = 'processing'
        
        # Initialiser Sender
        sender = LogstashSender(LOGSTASH_HOST, LOGSTASH_PORT, index_name)
        sender.start()
        
        results = []
        files_processed = 0
        
        # ThreadPool pour le parsing
        # On limite le nombre de workers pour ne pas tuer le CPU/Disque
        MAX_WORKERS = 4 
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_file = {
                executor.submit(process_file_worker, ffile, sender, index_name): ffile 
                for ffile in forensic_files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                ffile = future_to_file[future]
                try:
                    count, error = future.result()
                    
                    files_processed += 1
                    upload_tasks[task_id]['current'] = files_processed
                    upload_tasks[task_id]['current_file'] = ffile['relative_path']
                    # On évite le print excessif en parallèle, ou alors juste un log simple
                    # print(f"✅ {ffile['relative_path']} : {count} events")
                    
                    results.append({
                        'file': ffile['relative_path'],
                        'type': ffile['type'],
                        'size': ffile['size'],
                        'events_sent': count, # Note: c'est le count parsé, pas forcément encore envoyé (async)
                        'error': error,
                        'status': 'success' if not error else 'error'
                    })
                    
                except Exception as exc:
                    print(f"❌ Exception worker sur {ffile['relative_path']}: {exc}")
        
        # Attendre la fin de l'envoi
        sender.stop()
        total_events = sender.total_sent
        
        # 4. Data View
        data_view_created = create_kibana_data_view(index_name)
        successful_files = sum(1 for r in results if r['status'] == 'success')
        
        upload_tasks[task_id]['result'] = {
            'success': True,
            'message': f'Optimized Import terminé! {total_events} événements.',
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
        if sender: sender.stop()
             
    finally:
        def clean_temp():
            time.sleep(300)
            try:
                shutil.rmtree(extract_dir, ignore_errors=True)
            except: pass
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
