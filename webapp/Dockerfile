FROM python:3.11-slim

WORKDIR /app

# Installer les dépendances système (incluant celles pour Volatility3)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    python3-dev \
    libyara-dev \
    libmagic1 \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Copier et installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Créer le dossier pour les symbol tables Volatility3
RUN mkdir -p /app/symbols/windows && \
    echo "Symbols directory created. Download ISF files as needed."

# Copier le code de l'application
COPY . .

# Créer le dossier uploads
RUN mkdir -p /app/uploads

# Exposer le port
EXPOSE 8080

# Lancer l'application
CMD ["python", "app.py"]
