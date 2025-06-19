# web/app/models.py

"""
Modèles SQLAlchemy pour TSAR :

* **Project**: Conteneur pour une mission de pentest (cible, rapports, fichiers).
* **ProjectFile**: Fichiers divers uploadés pour un projet.
* **Report**: PDF chiffré généré après l'exécution d'un module.
* **Vulnerability**: Une vulnérabilité (CVE) identifiée dans un rapport. # NOUVEAU
* **ScanLog**: Trace légère de chaque exécution "live" (terminal).
* **UserProfile**: Profil utilisateur personnalisé (photo, nom).
* **ScheduledTask**: Tâches planifiées pour exécution automatique.
"""

from datetime import datetime, time, timedelta
from . import db


# ───────────────────────────── Project ─────────────────────────────
class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Project #{self.id} '{self.name}'>"


# ─────────────────────────── ProjectFile ───────────────────────────
class ProjectFile(db.Model):
    __tablename__ = "project_files"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(
        db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    user_sub = db.Column(db.String(128), nullable=False, index=True)
    filename = db.Column(db.Text, nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    mime_type = db.Column(db.String(100), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    project = db.relationship(
        "Project", backref=db.backref("files", lazy=True, cascade="all, delete-orphan")
    )

    def __repr__(self) -> str:
        return f"<ProjectFile #{self.id} '{self.filename}'>"


# ───────────────────────────── Report ──────────────────────────────
class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=True)
    filename = db.Column(db.Text, nullable=False)
    pdf_data = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    project = db.relationship("Project", backref=db.backref("reports", lazy=True))
    # NOUVEAU : Relation vers les vulnérabilités trouvées dans ce rapport
    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="report",
        lazy=True,
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Report #{self.id} {self.filename}>"


# ────────────────────────── Vulnerability (NOUVEAU) ──────────────────
class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer, db.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False
    )
    user_sub = db.Column(db.String(128), nullable=False, index=True)
    cve_id = db.Column(db.String(30), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    summary = db.Column(db.Text, nullable=True)
    component = db.Column(db.Text, nullable=True)
    found_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id} in Report #{self.report_id}>"


# ───────────────────────────── ScanLog ─────────────────────────────
class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=True)
    module = db.Column(db.String(64), nullable=False)
    target = db.Column(db.Text, nullable=True)
    mode = db.Column(db.String(16), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    project = db.relationship("Project", backref=db.backref("scan_logs", lazy=True))

    def __repr__(self) -> str:
        return (
            f"<ScanLog #{self.id} {self.module} "
            f"{self.target or '(no target)'} {self.mode}>"
        )


# ───────────────────────────── UserProfile ─────────────────────────
class UserProfile(db.Model):
    __tablename__ = "user_profiles"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=True)
    avatar_data = db.Column(db.LargeBinary, nullable=True)
    avatar_mime = db.Column(db.String(50), nullable=True)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def __repr__(self) -> str:
        return f"<UserProfile {self.user_sub} '{self.display_name or 'No name'}'>"


# ───────────────────────────── ScheduledTask ───────────────────────
class ScheduledTask(db.Model):
    __tablename__ = "scheduled_tasks"

    id = db.Column(db.Integer, primary_key=True)
    user_sub = db.Column(db.String(128), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    module_name = db.Column(db.String(64), nullable=False)
    target = db.Column(db.Text, nullable=True)
    mode = db.Column(db.String(16), nullable=False)
    schedule_type = db.Column(db.String(20), nullable=False)
    schedule_time = db.Column(db.Time, nullable=False)
    schedule_day = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<ScheduledTask #{self.id} '{self.name}' {self.schedule_type}>"

    def calculate_next_run(self, from_date: datetime | None = None) -> datetime:
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
            if run_date.day > target_day or (
                run_date.day == target_day and now.time() >= self.schedule_time
            ):
                run_date = (run_date.replace(day=1) + timedelta(days=32)).replace(day=1)
            try:
                run_date = run_date.replace(day=target_day)
            except ValueError:
                next_month = (run_date.replace(day=1) + timedelta(days=32)).replace(day=1)
                run_date = next_month - timedelta(days=1)

        return datetime.combine(run_date, self.schedule_time)
