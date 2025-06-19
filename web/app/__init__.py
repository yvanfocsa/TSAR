# web/app/__init__.py
from __future__ import annotations

import time
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
import pytz
from celery import Celery
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config

db = SQLAlchemy()
oauth = OAuth()

def make_celery(app: Flask) -> Celery:
    """Crée et configure une instance Celery pour l'application Flask."""
    celery_app = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'], # Utilise la clé du config Flask
        backend=app.config['CELERY_RESULT_BACKEND'] # Utilise la clé du config Flask
    )
    
    # MODIFIÉ : Supprimer cette ligne qui cause le conflit
    # celery_app.conf.update(app.config) 

    class ContextTask(celery_app.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery_app.Task = ContextTask
    return celery_app

def route_tasks(name, args, kwargs, options, task=None, **kw):
    if name == 'app.tasks.run_job' and args:
        module_name = args[0]
        # MODIFIÉ : "Omega Scan (OSINT)" a été retiré de la liste
        long_running_modules = [
            "Vuln Assessment – Complet", 
            "Metasploit - Scan d'Exploits Potentiels",
            "Audit Agressif (Nmap + Nuclei + Metasploit)"
        ]
        if module_name in long_running_modules:
            return {'queue': 'long_queue'}
    return {'queue': 'default_queue'}

def create_app(register_blueprints=True, register_context_processors=True) -> Flask:
    """Factory principale : instancie Flask, BD, OAuth, modules, routes."""
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    app.config.from_object(Config)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1, x_proto=1, x_port=1)
    app.config['PREFERRED_URL_SCHEME'] = 'https'

    celery_app = make_celery(app)
    celery_app.conf.imports = ('app.tasks',)
    celery_app.conf.task_routes = (route_tasks,)
    celery_app.conf.beat_schedule = {
       'check-scheduled-tasks-every-minute': {
           'task': 'app.tasks.check_scheduled_tasks',
           'schedule': 60.0,
       },
    }
    app.celery = celery_app

    app.jinja_env.filters['paris_time'] = format_paris_time

    db.init_app(app)
    with app.app_context():
        from . import models
        db.create_all()

    oauth.init_app(app)
    oauth.register(
        name="auth0",
        client_id=app.config["AUTH0_CLIENT_ID"],
        client_secret=app.config["AUTH0_CLIENT_SECRET"],
        client_kwargs={"scope": "openid profile email"},
        server_metadata_url=(
            f'https://{app.config["AUTH0_DOMAIN"]}'
            '/.well-known/openid-configuration'
        ),
    )
    app.oauth = oauth

    from . import modules as modules_loader # Importation du module modules.py
    modules_loader.load_modules() # Charger les modules
    app.modules_obj = modules_loader # Rendre l'objet module_loader accessible via l'application

    if register_blueprints:
        from .routes import login_manager, bp as routes_bp
        login_manager.login_view = "routes.login"
        login_manager.init_app(app)
        app.register_blueprint(routes_bp)

    if register_context_processors:
        @app.context_processor
        def inject_user_info():
            from flask import session
            from flask_login import current_user
            from .models import UserProfile

            if not current_user.is_authenticated:
                return dict(display_name="Utilisateur", email=None, profile=None)

            profile = UserProfile.query.filter_by(user_sub=current_user.sub).first()
            user_data = session.get("user", {})
            email = user_data.get("email")

            if profile and profile.display_name:
                display_name = profile.display_name
            else:
                auth0_name = user_data.get("nickname") or user_data.get("name")
                if auth0_name and "@" not in auth0_name:
                    display_name = auth0_name
                elif email:
                    display_name = email.split('@')[0]
                else:
                    display_name = "Utilisateur"
            
            return dict(display_name=display_name, email=email, profile=profile)

        @app.context_processor
        def inject_utility_processor():
            return dict(cache_buster=int(time.time()))

    return app

def format_paris_time(utc_dt):
    if not utc_dt:
        return "N/A"
    paris_tz = pytz.timezone('Europe/Paris')
    paris_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(paris_tz)
    return paris_dt.strftime('%d/%m/%Y à %Hh%M')
