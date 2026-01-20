const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const progressContainer = document.getElementById('progress-container');
const progressFill = document.querySelector('.progress-fill');
const progressText = document.querySelector('.progress-text');
const resultsContainer = document.getElementById('results-container');
const resultsBody = document.querySelector('.results-table tbody');
const resultsSummary = document.querySelector('.results-summary');
const kibanaLink = document.getElementById('kibana-link');
const errorContainer = document.getElementById('error-container');
const errorMessage = document.getElementById('error-message');
const passwordModal = document.getElementById('password-modal');
const zipPassword = document.getElementById('zip-password');
const btnSubmitPassword = document.getElementById('btn-submit-password') || document.getElementById('submit-password');
const statusDots = {
    webapp: document.getElementById('status-webapp'),
    logstash: document.getElementById('status-logstash'),
    evtx: document.getElementById('status-evtx')
};

// Événements Drag & Drop
['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, preventDefaults, false);
});

function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, highlight, false);
});

['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, unhighlight, false);
});

function highlight() {
    dropZone.classList.add('drag-active');
}

function unhighlight() {
    dropZone.classList.remove('drag-active');
}

dropZone.addEventListener('drop', handleDrop, false);

// Gestion du clic sur la zone de drop pour ouvrir l'explorateur
dropZone.addEventListener('click', () => {
    fileInput.click();
});

function handleDrop(e) {
    const dt = e.dataTransfer;
    const file = dt.files[0];
    handleFile(file);
}

fileInput.addEventListener('change', function () {
    if (this.files && this.files[0]) {
        handleFile(this.files[0]);
    }
});

// Variable globale pour stocker le fichier en attente de mot de passe
let currentFile = null;

function handleFile(file) {
    if (!file) return;
    currentFile = file;
    zipPassword.value = ''; // Reset mot de passe
    uploadWithPassword(file);
}

// Gestion des boutons de presets de mot de passe
document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const pwd = btn.getAttribute('data-password');
        if (pwd) {
            zipPassword.value = pwd;
            zipPassword.focus();
        }
    });
});

// Gestion de la modal mot de passe
if (btnSubmitPassword) {
    btnSubmitPassword.addEventListener('click', () => {
        if (currentFile) {
            uploadWithPassword(currentFile, zipPassword.value);
        }
    });
}
zipPassword.addEventListener('keypress', (e) => {
    if (e.key === 'Enter' && currentFile) {
        uploadWithPassword(currentFile, zipPassword.value);
    }
});

// Bouton Annuler mot de passe
const btnCancel = document.querySelector('#cancel-password');
if (btnCancel) {
    btnCancel.addEventListener('click', () => {
        hidePasswordModal();
        resetUpload();
    });
}

// Boutons de résultat (Nouvel upload / Réessayer)
document.addEventListener('click', (e) => {
    if (e.target.id === 'new-upload-btn' || e.target.id === 'retry-btn') {
        resetUpload();
    }
});

/**
 * Upload le fichier avec un mot de passe optionnel
 */
function uploadWithPassword(file, password = null) {
    // UI Reset
    showProgress();
    updateProgress(0, 'Préparation de l\'envoi...');

    const formData = new FormData();
    formData.append('file', file);

    // Ajouter le mot de passe si présent
    if (password) {
        formData.append('password', password);
        console.log('🔐 Mot de passe fourni');
    }

    // Utiliser XMLHttpRequest pour avoir la progression de l'upload
    const xhr = new XMLHttpRequest();

    xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
            // Upload = 0-50% de la barre totale
            const percent = Math.round((e.loaded / e.total) * 50);
            updateProgress(percent, 'Upload: ' + formatSize(e.loaded) + ' / ' + formatSize(e.total));
        }
    });

    xhr.upload.addEventListener('loadend', () => {
        console.log('📤 Upload terminé, démarrage du traitement...');
        updateProgress(50, 'Upload terminé, initialisation du traitement...');
    });

    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4) {
            console.log('📡 Réponse upload reçue, status:', xhr.status);

            if (xhr.status === 0) {
                console.error('❌ Erreur réseau');
                showError('Erreur réseau - le serveur est inaccessible');
                return;
            }

            try {
                const result = JSON.parse(xhr.responseText);

                // Cas 1: 202 DataViewAccepted -> Tâche démarrée
                if (xhr.status === 202) {
                    console.log('✅ Tâche démarrée:', result.task_id);
                    pollTaskStatus(result.task_id);
                    return;
                }

                // Cas 2: 400 Bad Request (ex: mot de passe requis)
                if (xhr.status === 400) {
                    if (result.password_required) {
                        console.log('🔒 Mot de passe requis');
                        showPasswordModal();
                    } else {
                        showError(result.error || 'Erreur requête invalide');
                    }
                    return;
                }

                // Cas 3: Autres erreurs
                if (xhr.status !== 200) {
                    showError(result.error || 'Erreur serveur: ' + xhr.status);
                    return;
                }

                // Fallback (si jamais 200 direct)
                updateProgress(100, 'Terminé!');
                showResults(result);

            } catch (e) {
                console.error('❌ Erreur parsing JSON:', e);
                showError('Erreur de réponse du serveur');
            }
        }
    };

    xhr.addEventListener('error', (e) => {
        console.error('❌ Erreur XHR:', e);
        showError('Erreur réseau');
    });

    console.log('🌐 Envoi vers /api/upload...');
    xhr.open('POST', '/api/upload');
    xhr.send(formData);
}

/**
 * Polling de l'état de la tâche
 */
function pollTaskStatus(taskId) {
    const pollInterval = setInterval(() => {
        fetch(`/api/task/${taskId}`)
            .then(res => res.json())
            .then(task => {
                // console.log('🔄 Status:', task.status);

                if (task.status === 'error') {
                    clearInterval(pollInterval);
                    if (task.password_required) {
                        showPasswordModal();
                    } else {
                        showError(task.error || 'Erreur lors du traitement');
                    }
                    return;
                }

                if (task.status === 'completed') {
                    clearInterval(pollInterval);
                    updateProgress(100, 'Traitement terminé !');
                    setTimeout(() => showResults(task.result), 500);
                    return;
                }

                // Mise à jour progression
                if (task.status === 'extracting') {
                    updateProgress(55, 'Extraction du ZIP...');
                } else if (task.status === 'scanning') {
                    updateProgress(60, 'Scan des fichiers...');
                } else if (task.status === 'processing') {
                    // Calcul pourcentage entre 60% et 95%
                    const tasksPercent = task.total > 0 ? (task.current / task.total) : 0;
                    const visualPercent = 60 + Math.round(tasksPercent * 35);

                    updateProgress(
                        visualPercent,
                        `Traitement: ${task.current}/${task.total} - ${truncate(task.current_file || '', 30)}`
                    );
                } else if (task.status === 'starting') {
                    updateProgress(52, 'Démarrage...');
                }
            })
            .catch(err => {
                console.error('Erreur polling:', err);
                // On ne coupe pas forcément l'intervalle sur une erreur réseau passagère
            });
    }, 1000); // Check toutes les 1s
}


function resetUpload() {
    fileInput.value = '';
    dropZone.classList.remove('drag-active');

    // Réinitialiser les affichages
    dropZone.style.display = 'block';
    progressContainer.style.display = 'none';
    resultsContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    passwordModal.style.display = 'none';
}

function showPasswordModal() {
    passwordModal.style.display = 'flex';
    dropZone.style.display = 'none';
    progressContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    zipPassword.focus();
}

function hidePasswordModal() {
    passwordModal.style.display = 'none';
}

function showProgress() {
    dropZone.style.display = 'none';
    progressContainer.style.display = 'block';
    resultsContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    passwordModal.style.display = 'none';
}

function updateProgress(percent, text) {
    progressFill.style.width = percent + '%';
    progressText.textContent = text;
}

function showResults(result) {
    progressContainer.style.display = 'none';
    resultsContainer.style.display = 'block';

    // Message de succès
    const successBanner = result.message || 'Import terminé!';
    const dataViewStatus = result.data_view_created ? '✅ Data View créé' : '⚠️ Data View non créé';

    // Résumé
    resultsSummary.innerHTML = `
        <div class="success-banner">
            🎉 ${successBanner}
            <small>${dataViewStatus}</small>
        </div>
        <div class="summary-grid">
            <div class="summary-item">
                <span class="summary-value">${result.files_found || result.files_processed}</span>
                <span class="summary-label">Fichiers trouvés</span>
            </div>
            <div class="summary-item">
                <span class="summary-value">${result.files_processed}</span>
                <span class="summary-label">Fichiers traités</span>
            </div>
            <div class="summary-item">
                <span class="summary-value">${formatNumber(result.total_events)}</span>
                <span class="summary-label">Événements</span>
            </div>
        </div>
        <div class="index-info">
            📊 Index: <code>${result.index_name}</code>
        </div>
    `;

    // Tableau des fichiers
    resultsBody.innerHTML = '';

    result.details.forEach(file => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td title="${file.file}">${truncate(file.file, 40)}</td>
            <td>${file.type}</td>
            <td>${formatSize(file.size)}</td>
            <td>${formatNumber(file.events_sent)}</td>
            <td>
                <span class="status-badge ${file.status}">
                    ${file.status === 'success' ? '✓ OK' : '✗ Erreur'}
                </span>
                ${file.error ? '<br><small style="color: var(--text-muted);">' + file.error + '</small>' : ''}
            </td>
        `;
        resultsBody.appendChild(row);
    });

    // Lien Kibana avec le bon Data View
    kibanaLink.href = result.kibana_url || 'http://localhost:5601/app/discover';
}

function showError(message) {
    dropZone.style.display = 'none';
    progressContainer.style.display = 'none';
    resultsContainer.style.display = 'none';
    errorContainer.style.display = 'block';
    passwordModal.style.display = 'none';

    errorMessage.textContent = message;
}

// Utilitaires de formatage
function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatNumber(num) {
    return new Intl.NumberFormat('fr-FR').format(num);
}

function truncate(str, n) {
    return (str.length > n) ? str.substr(0, n - 1) + '...' : str;
}

// Vérification du statut des services
function checkStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            updateStatusDot(statusDots.webapp, data.webapp === 'ok');
            updateStatusDot(statusDots.logstash, data.logstash === 'ok');
            updateStatusDot(statusDots.evtx, data.evtx_support);
        })
        .catch(() => {
            updateStatusDot(statusDots.webapp, false);
            updateStatusDot(statusDots.logstash, false);
            updateStatusDot(statusDots.evtx, false);
        });
}

function updateStatusDot(element, isOk) {
    if (!element) return;
    // La classe ok/error doit être sur le parent (.status-item)
    // C'est ce que element est (d'après les IDs dans HTML)
    element.classList.remove('ok', 'error');
    element.classList.add(isOk ? 'ok' : 'error');
}

// Vérifier le statut au chargement puis toutes les 30s
checkStatus();
setInterval(checkStatus, 30000);
