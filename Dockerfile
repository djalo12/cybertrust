FROM python:3.11-slim

WORKDIR /app

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copie des fichiers de dépendances
COPY requirements.txt .

# Création du fichier requirements.txt si non existant
RUN if [ ! -f requirements.txt ]; then \
    echo "beautifulsoup4==4.12.2" > requirements.txt && \
    echo "email-validator==2.1.0" >> requirements.txt && \
    echo "flask==3.0.0" >> requirements.txt && \
    echo "flask-caching==2.1.0" >> requirements.txt && \
    echo "flask-login==0.6.3" >> requirements.txt && \
    echo "flask-sqlalchemy==3.1.1" >> requirements.txt && \
    echo "flask-wtf==1.2.1" >> requirements.txt && \
    echo "gunicorn==21.2.0" >> requirements.txt && \
    echo "psycopg2-binary==2.9.9" >> requirements.txt && \
    echo "python-whois==0.8.0" >> requirements.txt && \
    echo "requests==2.31.0" >> requirements.txt && \
    echo "trafilatura==1.6.3" >> requirements.txt; \
    fi

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code de l'application
COPY . .

# Exposition du port
EXPOSE 5000

# Commande de démarrage avec Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--timeout", "120", "main:app"]