import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev")
    
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5373")
    PIVOT_PUBLIC_URL = os.environ.get("PIVOT_PUBLIC_URL", "")

    AUTH0_DOMAIN         = os.environ.get("AUTH0_DOMAIN", "")
    AUTH0_CLIENT_ID      = os.environ.get("AUTH0_CLIENT_ID", "")
    AUTH0_CLIENT_SECRET  = os.environ.get("AUTH0_CLIENT_SECRET", "")
    AUTH0_AUDIENCE       = os.environ.get("AUTH0_AUDIENCE", "")
    AUTH0_CALLBACK_URL   = os.environ.get("AUTH0_CALLBACK_URL", "")

    PDF_ENC_KEY = os.environ.get("PDF_ENC_KEY", "")

    POSTGRES_USER     = os.environ.get("POSTGRES_USER", "tsar")
    POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "tsarpass")
    POSTGRES_DB       = os.environ.get("POSTGRES_DB", "tsar")

    SQLALCHEMY_DATABASE_URI = (
        f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASSWORD}@db:5432/{POSTGRES_DB}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # MODIFIÉ : On garde les noms de variables attendus par Flask et Celery dans make_celery
    # Les variables d'environnement 'broker_url' et 'result_backend' sont toujours lues par docker-compose
    # et passées aux conteneurs. Ici, on les mappe aux noms attendus par le code Python.
    CELERY_BROKER_URL = os.environ.get("broker_url", "redis://redis:6379/0")
    CELERY_RESULT_BACKEND = os.environ.get("result_backend", "redis://redis:6379/0")

    TOOLBOX_CONTAINER = os.environ.get("TOOLBOX_CONTAINER", "toolbox")
