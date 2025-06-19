###############################################################################
#                    Dockerfile – Conteneur “web” (Flask)                     #
###############################################################################

FROM python:3.12-slim

# ─────────────────────────── Pré-réglages de base ────────────────────────────
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1  \
    PYTHONUNBUFFERED=1

# ────────────────────────── Dépendances système utiles ───────────────────────
# FIX: Toutes les commandes sur une seule ligne pour éviter les erreurs de parsing.
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    build-essential \
    wkhtmltopdf \
    ca-certificates \
    tzdata \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# NOUVEAU : Configuration du fuseau horaire
ENV TZ=Europe/Paris
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# ─────────────────────────── Install deps Python ─────────────────────────────
COPY web/requirements.txt .

# (plus de torch / transformers ; requirements.txt est allégé)
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ─────────────────────── Copie du code applicatif (+ modules) ────────────────
COPY web/ .
COPY modules/ ./modules

# ────────────────────────── Variables d’environnement ────────────────────────
ENV FLASK_APP=app:create_app   \
    FLASK_RUN_HOST=0.0.0.0     \
    FLASK_RUN_PORT=5373

EXPOSE 5373

# ─────────────────────────── Commande de démarrage ───────────────────────────
# --reload : hot-reload pratique en dev ; en prod, préférer gunicorn/uwsgi
CMD ["flask", "run", "--reload"]
