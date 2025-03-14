# Déploiement de CyberTrust sur AWS Elastic Beanstalk

Ce guide vous explique comment déployer CyberTrust sur AWS Elastic Beanstalk, une solution de déploiement plus simple par rapport à l'installation sur EC2.

## Prérequis

1. Un compte AWS
2. L'AWS CLI installé et configuré
3. L'EB CLI installé : `pip install awsebcli`

## Préparation des fichiers de configuration

### 1. Créer un fichier Procfile

Créez un fichier nommé `Procfile` (sans extension) à la racine de votre projet :

```
web: gunicorn --bind 0.0.0.0:5000 --workers 3 --timeout 120 main:app
```

### 2. Créer un fichier .ebextensions/01_flask.config

Créez un dossier `.ebextensions` et ajoutez un fichier `01_flask.config` :

```yaml
option_settings:
  aws:elasticbeanstalk:container:python:
    WSGIPath: main:app
  aws:elasticbeanstalk:application:environment:
    FLASK_ENV: production
    DATABASE_URL: postgresql://username:password@YOUR-RDS-ENDPOINT:5432/cybertrust
  aws:elasticbeanstalk:environment:proxy:staticfiles:
    /static: static
```

### 3. Créer un fichier .ebignore (optionnel)

Pour éviter de télécharger des fichiers inutiles :

```
venv/
__pycache__/
.git/
*.pyc
```

## Création de la base de données RDS

1. Accédez à la console AWS et recherchez "RDS"
2. Cliquez sur "Create database"
3. Sélectionnez PostgreSQL
4. Choisissez la version appropriée (12 ou plus)
5. Configurez un nom d'utilisateur et un mot de passe
6. Notez l'endpoint de la base de données une fois créée

## Déploiement sur Elastic Beanstalk

### 1. Initialiser l'application EB

```bash
eb init -p python-3.11 cybertrust
```

### 2. Créer l'environnement et déployer

```bash
eb create cybertrust-env
```

### 3. Mises à jour futures

```bash
eb deploy
```

### 4. Ouvrir l'application dans le navigateur

```bash
eb open
```

## Configuration des variables d'environnement

Une fois l'environnement créé, vous pouvez configurer des variables d'environnement supplémentaires :

1. Allez dans la console EB
2. Sélectionnez votre environnement
3. Cliquez sur "Configuration"
4. Sous "Software", cliquez sur "Edit"
5. Ajoutez les variables d'environnement :
   - `SESSION_SECRET`: une valeur aléatoire
   - `DATABASE_URL`: l'URL de votre base de données RDS
   - Autres variables spécifiques si nécessaire

## Migration de la base de données

Pour effectuer la migration initiale de la base de données :

1. Connectez-vous à votre instance EB en SSH :
   ```
   eb ssh
   ```

2. Naviguez vers le répertoire de l'application :
   ```
   cd /var/app/current/
   ```

3. Créez un script de migration (si nécessaire) :
   ```python
   # migration.py
   from app import db
   db.create_all()
   ```

4. Exécutez le script :
   ```
   python migration.py
   ```

## Surveillance et logs

- Pour voir les logs : `eb logs`
- Pour surveiller la santé : `eb health`
- Pour consulter les événements : `eb events`

## Configuration avancée

Pour des options avancées comme l'équilibrage de charge, l'autoscaling, et la sécurité, consultez la documentation AWS Elastic Beanstalk.

## Gestion des coûts

Elastic Beanstalk est gratuit, mais vous payez pour les ressources sous-jacentes (EC2, RDS, etc.). Utilisez la calculatrice AWS pour estimer les coûts.

## Nettoyage des ressources

Lorsque vous n'avez plus besoin de l'environnement, supprimez-le pour éviter des coûts inutiles :

```bash
eb terminate cybertrust-env
```

---

Ce guide couvre les bases du déploiement sur Elastic Beanstalk. Pour plus de détails, consultez la [documentation officielle d'AWS](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/Welcome.html).