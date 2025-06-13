# web/app/models.py

"""
Modèles SQLAlchemy pour TSAR :

* **Report** : PDF chiffré généré après l'exécution d'un module.
* **ScanLog** : trace légère de chaque exécution "live" (terminal),
  affichée dans le tableau « Historique » du dashboard.
* **UserProfile** : profil utilisateur personnalisé (photo, nom).
* **ScheduledTask** : tâches planifiées pour exécution automatique.
"""

from datetime import datetime, time, timedelta
from . import db


# ───────────────────────────── Report ──────────────────────────────
class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False)  # sub Auth0
    filename = db.Column(db.Text, nullable=False)  # nom du PDF
    pdf_data = db.Column(db.LargeBinary, nullable=False)  # PDF chiffré
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Report #{self.id} {self.filename}>"


# ───────────────────────────── ScanLog ─────────────────────────────
class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False)  # sub Auth0
    module = db.Column(db.String(64), nullable=False)  # ex. "nmap"
    target = db.Column(db.Text, nullable=True)  # cible scannée
    mode = db.Column(db.String(16), nullable=False)  # quick / full / …
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return (
            f"<ScanLog #{self.id} {self.module} "
            f"{self.target or '(no target)'} {self.mode}>"
        )


# ───────────────────────────── UserProfile ─────────────────────────
class UserProfile(db.Model):
    __tablename__ = "user_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(
        db.String(128), unique=True, nullable=False
    )  # sub Auth0
    display_name = db.Column(
        db.String(100), nullable=True
    )  # nom personnalisé
    avatar_data = db.Column(
        db.LargeBinary, nullable=True
    )  # photo en binaire
    avatar_mime = db.Column(
        db.String(50), nullable=True
    )  # type MIME (image/jpeg, etc.)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self) -> str:
        return (
            f"<UserProfile {self.user_sub} '{self.display_name or 'No name'}'>"
        )


# ───────────────────────────── ScheduledTask ───────────────────────
class ScheduledTask(db.Model):
    __tablename__ = "scheduled_tasks"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False)  # sub Auth0
    name = db.Column(db.String(100), nullable=False)  # nom de la tâche
    module_name = db.Column(
        db.String(64), nullable=False
    )  # module à exécuter
    target = db.Column(db.Text, nullable=True)  # cible
    mode = db.Column(db.String(16), nullable=False)  # quick/full
    schedule_type = db.Column(
        db.String(20), nullable=False
    )  # daily, weekly, monthly
    schedule_time = db.Column(db.Time, nullable=False)  # heure d'exécution
    schedule_day = db.Column(
        db.Integer, nullable=True
    )  # jour du mois (1-31) ou jour semaine (0-6)
    is_active = db.Column(db.Boolean, default=True)  # activé/désactivé
    last_run = db.Column(db.DateTime, nullable=True)  # dernière exécution
    next_run = db.Column(db.DateTime, nullable=True)  # prochaine exécution
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<ScheduledTask #{self.id} '{self.name}' {self.schedule_type}>"

    def calculate_next_run(
        self, from_date: datetime | None = None
    ) -> datetime:
        """
        Calcule la prochaine date d'exécution de la tâche en se basant
        sur sa planification.
        """
        now = from_date or datetime.utcnow()
        run_date = now.date()

        if self.schedule_type == "daily":
            if now.time() >= self.schedule_time:
                run_date += timedelta(days=1)

        elif self.schedule_type == "weekly":
            target_weekday = self.schedule_day or 0  # 0 = Lundi
            days_ahead = target_weekday - run_date.weekday()
            if days_ahead < 0 or (
                days_ahead == 0 and now.time() >= self.schedule_time
            ):
                days_ahead += 7
            run_date += timedelta(days=days_ahead)

        elif self.schedule_type == "monthly":
            target_day = self.schedule_day or 1
            # Si la date/heure est déjà passée ce mois-ci, viser le mois prochain
            if run_date.day > target_day or (
                run_date.day == target_day
                and now.time() >= self.schedule_time
            ):
                run_date = (run_date.replace(day=1) + timedelta(days=32)).replace(
                    day=1
                )

            # Essayer de définir le jour, et gérer les mois trop courts
            try:
                run_date = run_date.replace(day=target_day)
            except ValueError:
                # Le jour n'existe pas (ex: 31 Février), prendre le dernier jour du mois
                next_month = (run_date.replace(day=1) + timedelta(days=32)).replace(
                    day=1
                )
                run_date = next_month - timedelta(days=1)

        return datetime.combine(run_date, self.schedule_time)
