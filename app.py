# CyberTrust - Analyse de la fiabilité des sites web et comptes sociaux
import os
import logging
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template, flash, redirect, url_for
from flask_caching import Cache
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from api.analyzer import analyze_url, analyze_social_account
from api.utils import normalize_url, extract_domain, is_valid_url, is_valid_social_platform

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "cybertrust-default-secret")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define models
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

class AnalysisCache(db.Model):
    """Modèle pour mettre en cache les résultats d'analyse"""
    id = db.Column(db.Integer, primary_key=True)
    # Type: website ou social_account
    type = db.Column(db.String(20), nullable=False)
    # Domaine ou plateforme+identifiant (renommé de target à identifier)
    identifier = db.Column(db.String(255), nullable=False, index=True)
    analysis_data = db.Column(db.Text, nullable=False)  # JSON stocké comme texte
    summary_note = db.Column(db.Text)  # Note récapitulative
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<AnalysisCache {self.id}: {self.type} - {self.identifier}>"
    
    def get_analysis_data(self):
        """Récupère les données d'analyse au format JSON"""
        return json.loads(self.analysis_data)
    
    def set_analysis_data(self, data):
        """Stocke les données d'analyse au format JSON"""
        self.analysis_data = json.dumps(data)

# Configure caching
cache_config = {
    "CACHE_TYPE": "SimpleCache",
    "CACHE_DEFAULT_TIMEOUT": 3600  # Cache results for 1 hour
}
app.config.from_mapping(cache_config)
cache = Cache(app)

# Add CSRF protection
csrf = CSRFProtect(app)

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    """Landing page with documentation and demo"""
    return render_template('index.html')

@app.route('/widget')
def widget_demo():
    """Demo page showing the widget in action"""
    return render_template('widget_demo.html')

@app.route('/report')
def report_form():
    """Page for reporting malicious websites or social accounts"""
    domain = request.args.get('domain')
    platform = request.args.get('platform')
    account = request.args.get('account')
    report_type = request.args.get('type')
    
    return render_template('report_form.html', 
                          domain=domain, 
                          platform=platform, 
                          account=account, 
                          type=report_type)

@app.route('/comment')
def comment_form():
    """Page for adding comments on websites or social accounts"""
    domain = request.args.get('domain')
    platform = request.args.get('platform')
    account = request.args.get('account')
    comment_type = request.args.get('type')
    
    return render_template('comment_form.html', 
                          domain=domain, 
                          platform=platform, 
                          account=account, 
                          type=comment_type)
                          
@app.route('/summary')
def summary():
    """Page showing a summary of analysis results"""
    url = request.args.get('url')
    social = request.args.get('social')
    account = request.args.get('account')
    
    if url:
        # Analyse de site web
        domain = extract_domain(url)
        try:
            # Récupérer l'analyse depuis le cache ou en effectuer une nouvelle
            cache_entry = AnalysisCache.query.filter_by(
                type='website',
                identifier=domain
            ).first()
            
            if not cache_entry:
                # Analyser et mettre en cache
                result = analyze_url(url)
                summary = generate_analysis_summary(result)
                cache_entry = AnalysisCache(
                    type='website',
                    identifier=domain,
                    analysis_data=json.dumps(result),
                    summary_note=summary
                )
                db.session.add(cache_entry)
                db.session.commit()
            
            # Récupérer les données d'analyse
            data = cache_entry.get_analysis_data()
            score = data.get('trust_score', 0)
            verdict = data.get('verdict', 'Inconnu')
            summary = cache_entry.summary_note.replace('\n', '<br>')
            
            return render_template('summary.html', 
                                  domain=domain, 
                                  score=score, 
                                  verdict=verdict, 
                                  summary=summary)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage du résumé pour {url}: {str(e)}")
            flash(f"Erreur lors de l'analyse de {url}: {str(e)}", 'danger')
            return redirect(url_for('index'))
            
    elif social and account:
        # Analyse de compte social
        try:
            target = f"{social}:{account}"
            # Récupérer l'analyse depuis le cache ou en effectuer une nouvelle
            cache_entry = AnalysisCache.query.filter_by(
                type='social',
                identifier=target
            ).first()
            
            if not cache_entry:
                # Analyser et mettre en cache
                result = analyze_social_account(social, account)
                summary = generate_analysis_summary(result)
                cache_entry = AnalysisCache(
                    type='social',
                    identifier=target,
                    analysis_data=json.dumps(result),
                    summary_note=summary
                )
                db.session.add(cache_entry)
                db.session.commit()
            
            # Récupérer les données d'analyse
            data = cache_entry.get_analysis_data()
            score = data.get('trust_score', 0)
            verdict = data.get('verdict', 'Inconnu')
            summary = cache_entry.summary_note.replace('\n', '<br>')
            
            return render_template('summary.html', 
                                  platform=social, 
                                  account=account, 
                                  score=score, 
                                  verdict=verdict, 
                                  summary=summary)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'affichage du résumé pour {social}/{account}: {str(e)}")
            flash(f"Erreur lors de l'analyse de {social}/{account}: {str(e)}", 'danger')
            return redirect(url_for('index'))
    
    else:
        flash("Veuillez fournir une URL ou un compte social à analyser", 'warning')
        return redirect(url_for('index'))

@app.route('/api/analyze', methods=['GET'])
@cache.cached(timeout=3600, query_string=True)
def analyze():
    """
    Main API endpoint for analyzing URLs or social media accounts
    
    Query parameters:
    - url: Website URL to analyze (e.g. example.com)
    - social: Social network name (e.g. twitter, facebook, leboncoin)
    - account: Account name/identifier on the social network
    
    Returns JSON with trustworthiness score and detailed analysis
    """
    url = request.args.get('url')
    social = request.args.get('social')
    account = request.args.get('account')
    
    if url:
        logger.debug(f"Analyzing URL: {url}")
        try:
            result = analyze_url(url)
            
            # Sauvegarder le résultat dans le cache de la base de données
            domain = extract_domain(url)
            try:
                # Vérifier si une entrée de cache existe déjà
                cache_entry = AnalysisCache.query.filter_by(
                    type='website',
                    identifier=domain
                ).first()
                
                if cache_entry:
                    # Mettre à jour l'entrée existante
                    cache_entry.set_analysis_data(result)
                    cache_entry.updated_at = datetime.utcnow()
                    # Générer la note récapitulative
                    cache_entry.summary_note = generate_analysis_summary(result)
                else:
                    # Créer une nouvelle entrée
                    cache_entry = AnalysisCache(
                        type='website',
                        identifier=domain,
                        analysis_data=json.dumps(result),
                        summary_note=generate_analysis_summary(result)
                    )
                    db.session.add(cache_entry)
                
                db.session.commit()
            except Exception as db_err:
                logger.error(f"Erreur lors de la mise en cache de l'analyse pour {domain}: {str(db_err)}")
                # Continuer même si la mise en cache échoue
            
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            return jsonify({
                "error": "Failed to analyze URL",
                "message": str(e),
                "success": False
            }), 500
    
    elif social and account:
        logger.debug(f"Analyzing social account: {social}/{account}")
        try:
            result = analyze_social_account(social, account)
            
            # Sauvegarder le résultat dans le cache de la base de données
            target = f"{social}:{account}"
            try:
                # Vérifier si une entrée de cache existe déjà
                cache_entry = AnalysisCache.query.filter_by(
                    type='social',
                    identifier=target
                ).first()
                
                if cache_entry:
                    # Mettre à jour l'entrée existante
                    cache_entry.set_analysis_data(result)
                    cache_entry.updated_at = datetime.utcnow()
                    # Générer la note récapitulative
                    cache_entry.summary_note = generate_analysis_summary(result)
                else:
                    # Créer une nouvelle entrée
                    cache_entry = AnalysisCache(
                        type='social',
                        identifier=target,
                        analysis_data=json.dumps(result),
                        summary_note=generate_analysis_summary(result)
                    )
                    db.session.add(cache_entry)
                
                db.session.commit()
            except Exception as db_err:
                logger.error(f"Erreur lors de la mise en cache de l'analyse pour {target}: {str(db_err)}")
                # Continuer même si la mise en cache échoue
            
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error analyzing social account {social}/{account}: {str(e)}")
            return jsonify({
                "error": "Failed to analyze social account",
                "message": str(e),
                "success": False
            }), 500
    
    else:
        return jsonify({
            "error": "Missing parameters",
            "message": "Please provide either 'url' parameter or both 'social' and 'account' parameters",
            "success": False
        }), 400

@app.route('/api/report/website', methods=['POST'])
def report_website():
    """API endpoint pour signaler un site web malveillant"""
    data = request.get_json() or {}
    domain = data.get('domain')
    reason = data.get('reason')
    details = data.get('details', '')
    
    if not domain or not reason:
        return jsonify({
            "error": "Missing parameters",
            "message": "Please provide 'domain' and 'reason' parameters",
            "success": False
        }), 400
    
    try:
        # Normaliser le domaine
        if domain.startswith('http'):
            domain = extract_domain(domain)
        
        # Créer le rapport
        report = Report(
            type='website',
            identifier=domain,
            reason=reason,
            details=details,
            reporter_ip=request.remote_addr
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Report submitted successfully",
            "domain": domain,
            "report_id": report.id
        })
    except Exception as e:
        logger.error(f"Error reporting website {domain}: {str(e)}")
        return jsonify({
            "error": "Failed to submit report",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/report/social', methods=['POST'])
def report_social():
    """API endpoint pour signaler un compte social malveillant"""
    data = request.get_json() or {}
    platform = data.get('platform')
    account_id = data.get('account_id')
    reason = data.get('reason')
    details = data.get('details', '')
    
    if not platform or not account_id or not reason:
        return jsonify({
            "error": "Missing parameters",
            "message": "Please provide 'platform', 'account_id', and 'reason' parameters",
            "success": False
        }), 400
    
    try:
        target = f"{platform}:{account_id}"
        
        # Créer le rapport
        report = Report(
            type='social_account',
            identifier=target,
            reason=reason,
            details=details,
            reporter_ip=request.remote_addr
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Report submitted successfully",
            "platform": platform,
            "account_id": account_id,
            "report_id": report.id
        })
    except Exception as e:
        logger.error(f"Error reporting social account {platform}/{account_id}: {str(e)}")
        return jsonify({
            "error": "Failed to submit report",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/comment/website', methods=['POST'])
def comment_website():
    """API endpoint pour commenter un site web"""
    data = request.get_json() or {}
    domain = data.get('domain')
    content = data.get('content')
    author_name = data.get('author_name', 'Anonymous')
    author_email = data.get('author_email', '')
    rating = data.get('rating')
    
    if not domain or not content:
        return jsonify({
            "error": "Missing parameters",
            "message": "Please provide 'domain' and 'content' parameters",
            "success": False
        }), 400
    
    try:
        # Normaliser le domaine
        if domain.startswith('http'):
            domain = extract_domain(domain)
        
        # Créer le commentaire
        comment = Comment(
            type='website',
            identifier=domain,
            content=content,
            author_name=author_name,
            author_email=author_email,
            author_ip=request.remote_addr,
            rating=rating
        )
        
        db.session.add(comment)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Comment submitted successfully",
            "domain": domain,
            "comment_id": comment.id
        })
    except Exception as e:
        logger.error(f"Error commenting on website {domain}: {str(e)}")
        return jsonify({
            "error": "Failed to submit comment",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/comment/social', methods=['POST'])
def comment_social():
    """API endpoint pour commenter un compte social"""
    data = request.get_json() or {}
    platform = data.get('platform')
    account_id = data.get('account_id')
    content = data.get('content')
    author_name = data.get('author_name', 'Anonymous')
    author_email = data.get('author_email', '')
    rating = data.get('rating')
    
    if not platform or not account_id or not content:
        return jsonify({
            "error": "Missing parameters",
            "message": "Please provide 'platform', 'account_id', and 'content' parameters",
            "success": False
        }), 400
    
    try:
        target = f"{platform}:{account_id}"
        
        # Créer le commentaire
        comment = Comment(
            type='social_account',
            identifier=target,
            content=content,
            author_name=author_name,
            author_email=author_email,
            author_ip=request.remote_addr,
            rating=rating
        )
        
        db.session.add(comment)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message": "Comment submitted successfully",
            "platform": platform,
            "account_id": account_id,
            "comment_id": comment.id
        })
    except Exception as e:
        logger.error(f"Error commenting on social account {platform}/{account_id}: {str(e)}")
        return jsonify({
            "error": "Failed to submit comment",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/comments/website/<domain>', methods=['GET'])
def get_website_comments(domain):
    """API endpoint pour récupérer les commentaires sur un site web"""
    try:
        # Normaliser le domaine
        if domain.startswith('http'):
            domain = extract_domain(domain)
        
        comments = Comment.query.filter_by(
            type='website',
            identifier=domain
        ).order_by(Comment.created_at.desc()).all()
        
        result = []
        for comment in comments:
            result.append({
                "id": comment.id,
                "content": comment.content,
                "author_name": comment.author_name,
                "rating": comment.rating,
                "is_verified": comment.is_verified,
                "created_at": comment.created_at.isoformat()
            })
        
        return jsonify({
            "success": True,
            "domain": domain,
            "comment_count": len(result),
            "comments": result
        })
    except Exception as e:
        logger.error(f"Error getting comments for website {domain}: {str(e)}")
        return jsonify({
            "error": "Failed to get comments",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/comments/social/<platform>/<account_id>', methods=['GET'])
def get_social_comments(platform, account_id):
    """API endpoint pour récupérer les commentaires sur un compte social"""
    try:
        target = f"{platform}:{account_id}"
        
        comments = Comment.query.filter_by(
            type='social_account',
            identifier=target
        ).order_by(Comment.created_at.desc()).all()
        
        result = []
        for comment in comments:
            result.append({
                "id": comment.id,
                "content": comment.content,
                "author_name": comment.author_name,
                "rating": comment.rating,
                "is_verified": comment.is_verified,
                "created_at": comment.created_at.isoformat()
            })
        
        return jsonify({
            "success": True,
            "platform": platform,
            "account_id": account_id,
            "comment_count": len(result),
            "comments": result
        })
    except Exception as e:
        logger.error(f"Error getting comments for social account {platform}/{account_id}: {str(e)}")
        return jsonify({
            "error": "Failed to get comments",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/reports/website/<domain>', methods=['GET'])
def get_website_reports(domain):
    """API endpoint pour récupérer le nombre de signalements sur un site web"""
    try:
        # Normaliser le domaine
        if domain.startswith('http'):
            domain = extract_domain(domain)
        
        report_count = Report.query.filter_by(
            type='website',
            identifier=domain
        ).count()
        
        return jsonify({
            "success": True,
            "domain": domain,
            "report_count": report_count
        })
    except Exception as e:
        logger.error(f"Error getting reports for website {domain}: {str(e)}")
        return jsonify({
            "error": "Failed to get reports",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/reports/social/<platform>/<account_id>', methods=['GET'])
def get_social_reports(platform, account_id):
    """API endpoint pour récupérer le nombre de signalements sur un compte social"""
    try:
        target = f"{platform}:{account_id}"
        
        report_count = Report.query.filter_by(
            type='social_account',
            identifier=target
        ).count()
        
        return jsonify({
            "success": True,
            "platform": platform,
            "account_id": account_id,
            "report_count": report_count
        })
    except Exception as e:
        logger.error(f"Error getting reports for social account {platform}/{account_id}: {str(e)}")
        return jsonify({
            "error": "Failed to get reports",
            "message": str(e),
            "success": False
        }), 500

@app.route('/api/summary', methods=['GET'])
def get_analysis_summary():
    """
    Endpoint pour récupérer la note récapitulative de l'analyse
    
    Query parameters:
    - url: Website URL to get summary for
    - social: Social network name
    - account: Account name/identifier on the social network
    
    Returns summary text
    """
    url = request.args.get('url')
    social = request.args.get('social')
    account = request.args.get('account')
    
    if url:
        domain = extract_domain(url)
        try:
            cache_entry = AnalysisCache.query.filter_by(
                type='website',
                identifier=domain
            ).first()
            
            if cache_entry and cache_entry.summary_note:
                return jsonify({
                    "success": True,
                    "domain": domain,
                    "summary": cache_entry.summary_note
                })
            else:
                # Si pas dans le cache, générer à la volée
                result = analyze_url(url)
                summary = generate_analysis_summary(result)
                return jsonify({
                    "success": True,
                    "domain": domain,
                    "summary": summary
                })
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du résumé pour {domain}: {str(e)}")
            return jsonify({
                "error": "Failed to get summary",
                "message": str(e),
                "success": False
            }), 500
    
    elif social and account:
        target = f"{social}:{account}"
        try:
            cache_entry = AnalysisCache.query.filter_by(
                type='social',
                identifier=target
            ).first()
            
            if cache_entry and cache_entry.summary_note:
                return jsonify({
                    "success": True,
                    "platform": social,
                    "account": account,
                    "summary": cache_entry.summary_note
                })
            else:
                # Si pas dans le cache, générer à la volée
                result = analyze_social_account(social, account)
                summary = generate_analysis_summary(result)
                return jsonify({
                    "success": True,
                    "platform": social,
                    "account": account,
                    "summary": summary
                })
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du résumé pour {social}/{account}: {str(e)}")
            return jsonify({
                "error": "Failed to get summary",
                "message": str(e),
                "success": False
            }), 500
    
    else:
        return jsonify({
            "error": "Missing parameters",
            "message": "Please provide either 'url' parameter or both 'social' and 'account' parameters",
            "success": False
        }), 400

def generate_analysis_summary(result):
    """
    Génère une note récapitulative expliquant l'analyse de manière simple
    
    Args:
        result (dict): Résultat d'analyse
    
    Returns:
        str: Note récapitulative
    """
    trust_score = result.get('trust_score', 0)
    verdict = result.get('verdict', 'Inconnu')
    domain = result.get('domain', 'ce site')
    url = result.get('url', '')
    analysis = result.get('analysis', {})
    
    # Récupérer les détails pour chaque catégorie
    security = analysis.get('security', {})
    reputation = analysis.get('reputation', {})
    technical = analysis.get('technical', {})
    content = analysis.get('content', {})
    
    summary = f"Analyse de sécurité pour {domain} (Score: {trust_score}/100 - {verdict})\n\n"
    
    # Points forts
    strengths = []
    if security.get('score', 0) > (security.get('max_score', 30) * 0.7):
        strengths.append("la sécurité du site semble bonne")
    if reputation.get('score', 0) > (reputation.get('max_score', 30) * 0.7):
        strengths.append("la réputation en ligne est positive")
    if technical.get('score', 0) > (technical.get('max_score', 20) * 0.8):
        strengths.append("les aspects techniques sont bien gérés")
    if content.get('score', 0) > (content.get('max_score', 20) * 0.8):
        strengths.append("le contenu semble légitime")
    
    # Points faibles
    weaknesses = []
    if security.get('score', 0) < (security.get('max_score', 30) * 0.5):
        weaknesses.append("des problèmes de sécurité ont été détectés")
    if reputation.get('score', 0) < (reputation.get('max_score', 30) * 0.5):
        weaknesses.append("la réputation en ligne est préoccupante")
    if technical.get('score', 0) < (technical.get('max_score', 20) * 0.5):
        weaknesses.append("des faiblesses techniques ont été identifiées")
    if content.get('score', 0) < (content.get('max_score', 20) * 0.5):
        weaknesses.append("le contenu présente des signaux d'alerte")
    
    # Ajouter les points forts
    if strengths:
        summary += "Points forts : " + ", ".join(strengths) + ".\n\n"
    
    # Ajouter les points faibles
    if weaknesses:
        summary += "Points d'attention : " + ", ".join(weaknesses) + ".\n\n"
    
    # Recommandation finale
    if trust_score >= 75:
        summary += f"Recommandation : Ce site semble fiable, mais restez toujours vigilant lors de vos interactions en ligne."
    elif trust_score >= 50:
        summary += f"Recommandation : Ce site présente quelques risques. Soyez prudent, notamment pour les transactions financières."
    else:
        summary += f"Recommandation : Ce site présente des risques importants. Il est déconseillé de partager des informations personnelles ou financières."
    
    return summary

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error": "Not found",
        "message": "The requested resource was not found",
        "success": False
    }), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({
        "error": "Server error",
        "message": "An internal server error occurred",
        "success": False
    }), 500

@app.after_request
def add_header(response):
    """Add CORS headers to allow the widget to work on any website"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response