#!/bin/bash

# CyberTrust - AWS Deployment Script
# Ce script prépare l'environnement et installe toutes les dépendances nécessaires
# pour exécuter CyberTrust sur une instance AWS (Amazon Linux 2 / Ubuntu)

set -e  # Arrêter l'exécution si une commande échoue

echo "=== CyberTrust - Script de déploiement AWS ==="
echo "Ce script va installer toutes les dépendances nécessaires pour"
echo "exécuter l'application CyberTrust sur votre instance AWS."
echo ""

# Fonction pour détecter la distribution Linux
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
        echo "Système d'exploitation détecté : $OS $VERSION"
    else
        echo "Système d'exploitation non reconnu"
        exit 1
    fi
}

# Mise à jour du système
update_system() {
    echo ""
    echo "=== Mise à jour du système ==="
    if [[ "$OS" == *"Amazon Linux"* ]]; then
        sudo yum update -y
    elif [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        sudo apt-get update -y
        sudo apt-get upgrade -y
    else
        echo "Distribution non supportée pour la mise à jour automatique."
        echo "Veuillez mettre à jour votre système manuellement avant de continuer."
    fi
}

# Installation des dépendances système
install_system_dependencies() {
    echo ""
    echo "=== Installation des dépendances système ==="
    if [[ "$OS" == *"Amazon Linux"* ]]; then
        sudo yum install -y python3 python3-pip python3-devel postgresql-devel git wget curl openssl-devel libffi-devel gcc
    elif [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        sudo apt-get install -y python3 python3-pip python3-dev libpq-dev git wget curl libssl-dev libffi-dev gcc
    else
        echo "Distribution non supportée pour l'installation automatique des dépendances."
        echo "Veuillez installer les dépendances manuellement : python3, pip, postgresql-devel, etc."
    fi
}

# Installation et configuration de PostgreSQL
setup_postgresql() {
    echo ""
    echo "=== Installation et configuration de PostgreSQL ==="
    if [[ "$OS" == *"Amazon Linux"* ]]; then
        sudo amazon-linux-extras install -y postgresql14
        sudo yum install -y postgresql postgresql-server
        sudo postgresql-setup --initdb
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    elif [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        sudo apt-get install -y postgresql postgresql-contrib
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    else
        echo "Distribution non supportée pour l'installation automatique de PostgreSQL."
        echo "Veuillez installer PostgreSQL manuellement."
    fi
    
    echo "Configuration de la base de données PostgreSQL pour CyberTrust..."
    sudo -i -u postgres psql -c "CREATE USER cybertrust WITH PASSWORD 'cybertrust_password';"
    sudo -i -u postgres psql -c "CREATE DATABASE cybertrust;"
    sudo -i -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE cybertrust TO cybertrust;"
    
    echo "Base de données PostgreSQL configurée avec succès :"
    echo "- Base de données : cybertrust"
    echo "- Utilisateur : cybertrust"
    echo "- Mot de passe : cybertrust_password"
    echo "⚠️ IMPORTANT : Changez ce mot de passe en production !"
}

# Création de l'environnement virtuel Python
setup_python_env() {
    echo ""
    echo "=== Configuration de l'environnement Python ==="
    pip3 install --user virtualenv
    python3 -m virtualenv venv
    source venv/bin/activate
    
    # Installation des dépendances Python
    echo "Installation des dépendances Python..."
    pip install beautifulsoup4 email-validator flask flask-caching flask-login flask-sqlalchemy flask-wtf gunicorn psycopg2-binary python-whois requests trafilatura
    
    # Création du fichier requirements.txt
    pip freeze > requirements.txt
    echo "Fichier requirements.txt créé avec succès."
}

# Configuration des variables d'environnement
setup_environment() {
    echo ""
    echo "=== Configuration des variables d'environnement ==="
    cat > .env << EOL
# CyberTrust - Variables d'environnement
DATABASE_URL=postgresql://cybertrust:cybertrust_password@localhost/cybertrust
SESSION_SECRET=$(openssl rand -hex 32)
EOL
    
    echo "Fichier .env créé avec succès."
}

# Configuration de Gunicorn et Systemd
setup_gunicorn() {
    echo ""
    echo "=== Configuration de Gunicorn et Systemd ==="
    
    # Création du fichier de service systemd
    cat > cybertrust.service << EOL
[Unit]
Description=CyberTrust Gunicorn Service
After=network.target postgresql.service

[Service]
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
EnvironmentFile=$(pwd)/.env
ExecStart=$(pwd)/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 --timeout 120 main:app

[Install]
WantedBy=multi-user.target
EOL
    
    echo "Fichier de service cybertrust.service créé."
    echo "Pour l'installer, exécutez : sudo cp cybertrust.service /etc/systemd/system/"
    echo "Puis activez-le avec : sudo systemctl enable cybertrust.service"
    echo "Et démarrez-le avec : sudo systemctl start cybertrust.service"
}

# Instructions de configuration Nginx
nginx_instructions() {
    echo ""
    echo "=== Instructions pour configurer Nginx (optionnel) ==="
    echo "Pour améliorer les performances et la sécurité, vous pouvez utiliser Nginx comme proxy inverse."
    echo "Installez Nginx : sudo apt-get install -y nginx (Ubuntu) ou sudo yum install -y nginx (Amazon Linux)"
    
    cat > cybertrust.nginx.conf << EOL
server {
    listen 80;
    server_name votre-domaine.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static {
        alias $(pwd)/static;
        expires 30d;
    }
}
EOL
    
    echo "Fichier de configuration Nginx créé : cybertrust.nginx.conf"
    echo "Pour l'installer, modifiez le domaine et exécutez : sudo cp cybertrust.nginx.conf /etc/nginx/sites-available/cybertrust"
    echo "Puis créez un lien symbolique : sudo ln -s /etc/nginx/sites-available/cybertrust /etc/nginx/sites-enabled/"
    echo "Et redémarrez Nginx : sudo systemctl restart nginx"
}

# Instructions HTTPS avec Certbot
https_instructions() {
    echo ""
    echo "=== Instructions pour configurer HTTPS avec Let's Encrypt ==="
    echo "Pour sécuriser votre site avec HTTPS gratuit, installez Certbot :"
    echo "Ubuntu : sudo apt-get install -y certbot python3-certbot-nginx"
    echo "Amazon Linux : sudo yum install -y certbot python3-certbot-nginx"
    echo "Puis exécutez : sudo certbot --nginx -d votre-domaine.com"
}

# Instructions pour la migration/initialisation de la base de données
db_init_instructions() {
    echo ""
    echo "=== Instructions pour initialiser la base de données ==="
    echo "La base de données sera automatiquement initialisée au premier démarrage de l'application."
    echo "Pour forcer l'initialisation, vous pouvez exécuter le script suivant :"
    
    cat > initialize_db.py << EOL
from app import db

# Création des tables
db.create_all()

print("Base de données initialisée avec succès !")
EOL
    
    echo "Fichier initialize_db.py créé."
    echo "Pour l'exécuter : python initialize_db.py"
}

# Instructions finales
final_instructions() {
    echo ""
    echo "=== CyberTrust - Installation terminée ! ==="
    echo "Votre application CyberTrust est presque prête à être utilisée."
    echo ""
    echo "ÉTAPES SUIVANTES :"
    echo "1. Vérifiez et modifiez le fichier .env avec vos propres paramètres"
    echo "2. Installez le service systemd (voir instructions ci-dessus)"
    echo "3. Configurez Nginx comme proxy inverse (recommandé)"
    echo "4. Activez HTTPS avec Let's Encrypt pour une sécurité optimale"
    echo ""
    echo "Pour démarrer l'application manuellement : source venv/bin/activate && gunicorn --bind 0.0.0.0:5000 main:app"
    echo ""
    echo "Merci d'utiliser CyberTrust !"
}

# Exécution principale
detect_distro
update_system
install_system_dependencies
setup_postgresql
setup_python_env
setup_environment
setup_gunicorn
nginx_instructions
https_instructions
db_init_instructions
final_instructions