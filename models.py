"""
Modèles de base de données pour CyberTrust
"""
from datetime import datetime
from sqlalchemy import Integer, String, Text, Boolean, JSON, DateTime, Column, ForeignKey
from sqlalchemy.orm import relationship

class Report(db.Model):
    """Modèle pour les signalements de sites ou comptes malveillants"""
    id = db.Column(db.Integer, primary_key=True)
    # Type: website ou social_account
    type = db.Column(db.String(20), nullable=False)
    # Domaine ou plateforme+identifiant
    target = db.Column(db.String(255), nullable=False)
    reason = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    reporter_ip = db.Column(db.String(50))
    reported_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Report {self.id}: {self.type} - {self.target}>"
    
    @staticmethod
    def get_for_website(domain):
        """Récupérer les signalements pour un site web"""
        return Report.query.filter_by(type="website", target=domain).all()
    
    @staticmethod
    def get_for_social_account(platform, account_id):
        """Récupérer les signalements pour un compte social"""
        target = f"{platform}:{account_id}"
        return Report.query.filter_by(type="social_account", target=target).all()
    
    @staticmethod
    def count_for_website(domain):
        """Compter les signalements pour un site web"""
        return Report.query.filter_by(type="website", target=domain).count()
    
    @staticmethod
    def count_for_social_account(platform, account_id):
        """Compter les signalements pour un compte social"""
        target = f"{platform}:{account_id}"
        return Report.query.filter_by(type="social_account", target=target).count()

class Comment(db.Model):
    """Modèle pour les commentaires sur les sites ou comptes"""
    id = db.Column(db.Integer, primary_key=True)
    # Type: website ou social_account
    type = db.Column(db.String(20), nullable=False)
    # Domaine ou plateforme+identifiant
    target = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(100))
    author_email = db.Column(db.String(100))
    author_ip = db.Column(db.String(50))
    is_verified = db.Column(db.Boolean, default=False)
    rating = db.Column(db.Integer)  # Note de 1 à 5
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Comment {self.id}: {self.type} - {self.target}>"
    
    @staticmethod
    def get_for_website(domain):
        """Récupérer les commentaires pour un site web"""
        return Comment.query.filter_by(type="website", target=domain).order_by(Comment.created_at.desc()).all()
    
    @staticmethod
    def get_for_social_account(platform, account_id):
        """Récupérer les commentaires pour un compte social"""
        target = f"{platform}:{account_id}"
        return Comment.query.filter_by(type="social_account", target=target).order_by(Comment.created_at.desc()).all()

class AnalysisCache(db.Model):
    """Modèle pour mettre en cache les résultats d'analyse"""
    id = db.Column(db.Integer, primary_key=True)
    # Type: website ou social_account
    type = db.Column(db.String(20), nullable=False)
    # Domaine ou plateforme+identifiant
    target = db.Column(db.String(255), nullable=False, index=True)
    result = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f"<AnalysisCache {self.id}: {self.type} - {self.target}>"
    
    @staticmethod
    def get_for_website(domain):
        """Récupérer le cache pour un site web"""
        now = datetime.utcnow()
        return AnalysisCache.query.filter_by(
            type="website", 
            target=domain
        ).filter(AnalysisCache.expires_at > now).first()
    
    @staticmethod
    def get_for_social_account(platform, account_id):
        """Récupérer le cache pour un compte social"""
        now = datetime.utcnow()
        target = f"{platform}:{account_id}"
        return AnalysisCache.query.filter_by(
            type="social_account", 
            target=target
        ).filter(AnalysisCache.expires_at > now).first()

class AnalysisSummary(db.Model):
    """Modèle pour les résumés explicatifs des analyses"""
    id = db.Column(db.Integer, primary_key=True)
    # Type: website ou social_account
    type = db.Column(db.String(20), nullable=False)
    # Domaine ou plateforme+identifiant
    target = db.Column(db.String(255), nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)  # Score de confiance
    verdict = db.Column(db.String(50))  # Verdict textuel
    summary = db.Column(db.Text)  # Résumé explicatif
    highlights = db.Column(db.JSON)  # Points clés de l'analyse
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<AnalysisSummary {self.id}: {self.type} - {self.target}>"
    
    @staticmethod
    def get_for_website(domain):
        """Récupérer le résumé pour un site web"""
        return AnalysisSummary.query.filter_by(type="website", target=domain).order_by(AnalysisSummary.created_at.desc()).first()
    
    @staticmethod
    def get_for_social_account(platform, account_id):
        """Récupérer le résumé pour un compte social"""
        target = f"{platform}:{account_id}"
        return AnalysisSummary.query.filter_by(type="social_account", target=target).order_by(AnalysisSummary.created_at.desc()).first()