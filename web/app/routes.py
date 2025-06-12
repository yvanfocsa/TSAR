"""
Routes principaux : dashboard, exécution de modules, génération + téléchargement
de rapports et flux RSS.

Stack 100 % locale (pas d'IA) + Celery :
  • aucune importation directe de .tasks (évite les boucles)
  • appel asynchrone via current_app.celery.send_task(...)
"""

from __future__ import annotations

import io
import re  # ← Import pour les expressions régulières
import socket
from datetime import datetime, time, timedelta
from io import BytesIO
from typing import Any

import feedparser
import psutil
import requests
from bs4 import BeautifulSoup  # ← pour nettoyer le contenu RSS
from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from pdfminer.high_level import extract_text

from . import db
from .models import Report, ScanLog, ScheduledTask, UserProfile
from .modules import MODULES, get_categories
from .pdf_crypto import decrypt

# ─────────── Blueprint & LoginManager ───────────
bp = Blueprint("routes", __name__)
login_manager = LoginManager()
login_manager.login_view = "routes.login"


# ─────────── USER SESSION ───────────
class User(UserMixin):
    def __init__(self, sub: str, name: str):
        self.id = sub
        self.sub = sub
        self.name = name


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    data = session.get("user")
    if not data:
        return None
    return User(data["sub"], data.get("name", data.get("email", "")))


# ─────────── HELPERS ───────────
def _get_ips() -> tuple[str, str]:
    priv = socket.gethostbyname(socket.gethostname())
    try:
        pub = requests.get("https://api.ipify.org", timeout=2).text
    except requests.RequestException:
        pub = "n/a"
    return pub, priv


# ─────────── AUTH0 ───────────
@bp.route("/login")
def login():
    redirect_uri = url_for("routes.callback", _external=True)
    return current_app.oauth.auth0.authorize_redirect(
        redirect_uri=redirect_uri,
        audience=current_app.config["AUTH0_AUDIENCE"],
    )


@bp.route("/auth/callback")
def callback():
    token = current_app.oauth.auth0.authorize_access_token()
    user = current_app.oauth.auth0.parse_id_token(
        token, nonce=token.get("nonce")
    )
    session["user"] = dict(user)
    login_user(User(user["sub"], user.get("name", user.get("email", ""))))
    return redirect(url_for("routes.index"))


@bp.route("/logout")
def logout():
    logout_user()
    session.clear()
    return redirect(
        f'https://{current_app.config["AUTH0_DOMAIN"]}/v2/logout?'
        f'returnTo={url_for("routes.index", _external=True)}&'
        f'client_id={current_app.config["AUTH0_CLIENT_ID"]}'
    )


# ─────────── SECURITY ───────────
@bp.after_request
def security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com unpkg.com "
        "cdn.jsdelivr.net cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
        "font-src fonts.gstatic.com; "
        "img-src 'self' https: data:;"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ─────────── SYSTEM METRICS ───────────
@bp.route("/metrics/ram/json")
@login_required
def metrics_ram_json():
    mem = psutil.virtual_memory()
    used = (mem.total - mem.available) // 1024**2
    total = mem.total // 1024**2
    return jsonify({"used": used, "total": total})


# ─────────── DASHBOARD & CORE PAGES ───────────
@bp.route("/")
@login_required
def index():
    pub_ip, priv_ip = _get_ips()
    metrics = {
        "IP publique": pub_ip,
        "IP privée": priv_ip,
    }
    favoris = [m for m in MODULES if m["name"] in session.get("favorites", [])]
    logs = (
        ScanLog.query.filter_by(user_sub=current_user.sub)
        .order_by(ScanLog.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "dashboard.html", metrics=metrics, favoris=favoris, logs=logs
    )


@bp.route("/modules")
@login_required
def modules_home():
    cats = get_categories()

    # Définir l'ordre souhaité pour les catégories PTES et autres
    ptes_order = [
        "PTES - Phase 2",
        "PTES - Phase 4",
        "PTES - Phase 5",
        "PTES - Phase 6",
        "Active Directory",
        "Web",
        "OSINT",
    ]

    # Trier les catégories en fonction de la liste `ptes_order`
    sorted_cats = dict(
        sorted(
            cats.items(),
            key=lambda item: ptes_order.index(item[0])
            if item[0] in ptes_order
            else len(ptes_order),
        )
    )

    return render_template("modules.html", cats=sorted_cats)


@bp.route("/guide")
@login_required
def guide():
    return render_template("guide.html")


# ─────────── MODULES & JOBS ───────────
@bp.route("/modules/<name>/launch")
@login_required
def module_launcher(name: str):
    mod = next((m for m in MODULES if m["name"] == name), None)
    if not mod:
        abort(404)

    # NOUVEAU : Détecter l'IP publique spécifiquement pour le module VPN
    public_ip = None
    if name == 'IoT - Pivot VPN':
        try:
            # On ne garde que l'IP publique de la fonction helper
            public_ip = requests.get("https://api.ipify.org", timeout=2).text
        except requests.RequestException:
            public_ip = "Détection échouée"

    return render_template("module_launcher.html", mod=mod, public_ip=public_ip)


@bp.route("/modules/<name>/run", methods=["POST"])
@login_required
def module_run(name: str):
    mod = next((m for m in MODULES if m["name"] == name), None)
    if not mod:
        abort(404)

    params = {
        field["name"]: (
            request.form.getlist(field["name"])
            if field["type"] == "multiselect"
            else request.form.get(field["name"], "")
        )
        for field in mod.get("schema", [])
    }

    job = current_app.celery.send_task(
        "tsar.run_job", args=[name, params, current_user.sub]
    )
    return jsonify({"job_id": job.id})


@bp.route("/job/status/<job_id>")
@login_required
def job_status(job_id: str):
    """Vérifie l'état d'une tâche Celery."""
    from celery.result import AsyncResult

    task = AsyncResult(job_id, app=current_app.celery)
    response = {
        "state": task.state,
        "result": task.result if task.state == "SUCCESS" else None,
    }
    if task.state == "FAILURE":
        response["error"] = str(task.info)
    return jsonify(response)


# ─────────── FAVORIS ───────────
@bp.route("/modules/<name>/favorite", methods=["POST"])
@login_required
def toggle_favorite(name: str):
    fav: list[str] = session.setdefault("favorites", [])
    if name in fav:
        fav.remove(name)
    else:
        fav.append(name)
    session.modified = True
    star = "★" if name in fav else "☆"
    return (
        f'<button hx-post="{url_for("routes.toggle_favorite", name=name)}" '
        'hx-swap="outerHTML" class="fav-btn text-2xl">'
        f"{star}</button>",
        200,
        {"Content-Type": "text/html"},
    )


# ─────────── PDF REPORTS & COMPARISON ───────────
@bp.route("/reports")
@login_required
def reports():
    reps = (
        Report.query.filter_by(user_sub=current_user.sub)
        .order_by(Report.created_at.desc())
        .all()
    )
    mod_report = next(
        (m for m in MODULES if m["name"] == "7. Reporting"), None
    )
    targets = (
        ScanLog.query.filter_by(user_sub=current_user.sub)
        .filter(ScanLog.target.isnot(None))
        .with_entities(ScanLog.target)
        .distinct()
        .all()
    )
    return render_template(
        "reports.html",
        reports=reps,
        mod_report=mod_report,
        target_list=[t[0] for t in targets],
    )


@bp.route("/reports/<int:rid>")
@login_required
def download_report(rid: int):
    rep = Report.query.get_or_404(rid)
    if rep.user_sub != current_user.sub:
        abort(403)
    pdf = decrypt(rep.pdf_data)
    return send_file(
        BytesIO(pdf),
        as_attachment=True,
        download_name=rep.filename,
        mimetype="application/pdf",
    )


@bp.route("/reports/<int:rid>/delete", methods=["POST"])
@login_required
def delete_report(rid: int):
    """Supprime un rapport spécifique."""
    rep = Report.query.get_or_404(rid)

    if rep.user_sub != current_user.sub:
        abort(403)

    db.session.delete(rep)
    db.session.commit()

    return redirect(url_for("routes.reports"))


@bp.route("/compare", methods=["GET", "POST"])
@login_required
def compare_reports():
    """Compare two scan reports."""
    if request.method == "POST":
        report1_id = request.form.get("report1")
        report2_id = request.form.get("report2")

        if not report1_id or not report2_id:
            return "Veuillez sélectionner deux rapports à comparer.", 400

        report1 = Report.query.get_or_404(report1_id)
        report2 = Report.query.get_or_404(report2_id)

        if (
            report1.user_sub != current_user.sub
            or report2.user_sub != current_user.sub
        ):
            abort(403)

        try:
            pdf1_data = decrypt(report1.pdf_data)
            pdf2_data = decrypt(report2.pdf_data)
            text1 = extract_text(io.BytesIO(pdf1_data))
            text2 = extract_text(io.BytesIO(pdf2_data))
        except Exception as e:
            reports = (
                Report.query.filter_by(user_sub=current_user.sub)
                .order_by(Report.created_at.desc())
                .all()
            )
            return render_template(
                "compare_selection.html",
                reports=reports,
                error=f"Erreur lors de la lecture d'un PDF : {e}",
            )

        comparison = compare_texts(text1, text2)

        return render_template(
            "compare_results.html",
            report1=report1,
            report2=report2,
            comparison=comparison,
        )

    reports = (
        Report.query.filter_by(user_sub=current_user.sub)
        .order_by(Report.created_at.desc())
        .all()
    )
    return render_template("compare_selection.html", reports=reports)


def compare_texts(text1, text2):
    """Compare deux textes et retourne les différences structurées."""
    ports1 = set(extract_ports(text1))
    ports2 = set(extract_ports(text2))
    new_ports = sorted(list(ports2 - ports1))
    closed_ports = sorted(list(ports1 - ports2))

    vulns1 = set(extract_vulnerabilities(text1))
    vulns2 = set(extract_vulnerabilities(text2))
    new_vulns = sorted(list(vulns2 - vulns1))
    fixed_vulns = sorted(list(vulns1 - vulns2))

    return {
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "new_vulnerabilities": new_vulns,
        "fixed_vulnerabilities": fixed_vulns,
    }


def extract_ports(text):
    """Extrait les ports ouverts (ex: 80/tcp) mentionnés dans le texte."""
    return re.findall(r"^\s*(\d+/(?:tcp|udp))\s+open", text, re.MULTILINE)


def extract_vulnerabilities(text):
    """Extrait les vulnérabilités (CVE, Nuclei) mentionnées dans le texte."""
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    nuclei_vulns = re.findall(
        r"\[(.*?)\].*?\[(critical|high|medium|low|info)\].*?http", text
    )
    result = [c.upper() for c in cves]
    result.extend([f"{vuln.strip()} ({sev})" for vuln, sev in nuclei_vulns])
    return list(set(result))


# ─────────── CVE & COMPONENT ANALYSIS ───────────
@bp.route("/cve-analysis", methods=["GET", "POST"])
@login_required
def cve_analysis():
    reports = (
        Report.query.filter_by(user_sub=current_user.sub)
        .order_by(Report.created_at.desc())
        .all()
    )

    if request.method == "POST":
        job_id = None
        analysis_target = None
        task_name = None

        # Scénario 1: Analyse par ID de CVE
        if "cve_id" in request.form and request.form["cve_id"]:
            cve_id = request.form.get("cve_id", "").strip()
            job = current_app.celery.send_task(
                "tsar.run_cve_analysis", args=[cve_id]
            )
            analysis_target = cve_id

        # Scénario 2: Analyse par composants d'un rapport
        elif "report_id" in request.form and request.form["report_id"]:
            report_id = int(request.form["report_id"])
            report = Report.query.get(report_id)
            job = current_app.celery.send_task(
                "tsar.run_inference_analysis",
                args=[report_id, current_user.sub],
            )
            analysis_target = f"Rapport: {report.filename}"

        else:
            return render_template(
                "cve_analysis.html",
                reports=reports,
                error="Veuillez fournir un ID de CVE ou sélectionner un rapport.",
            )

        return render_template(
            "cve_analysis.html",
            reports=reports,
            job_id=job.id,
            analysis_target=analysis_target,
        )

    return render_template("cve_analysis.html", reports=reports)


# ─────────── PROFIL UTILISATEUR ───────────
@bp.route("/profile")
@login_required
def profile():
    """Page de paramètres du compte utilisateur."""
    profile = UserProfile.query.filter_by(user_sub=current_user.sub).first()

    scan_count = ScanLog.query.filter_by(user_sub=current_user.sub).count()
    report_count = Report.query.filter_by(user_sub=current_user.sub).count()
    favorite_count = len(session.get("favorites", []))

    stats = {
        "scans": scan_count,
        "reports": report_count,
        "favorites": favorite_count,
    }

    return render_template("profile.html", profile=profile, stats=stats)


@bp.route("/profile", methods=["POST"])
@login_required
def update_profile():
    """Mise à jour du profil utilisateur."""
    profile = UserProfile.query.filter_by(user_sub=current_user.sub).first()
    if not profile:
        profile = UserProfile(user_sub=current_user.sub)
        db.session.add(profile)

    display_name = request.form.get("display_name", "").strip()
    if display_name:
        profile.display_name = display_name

    avatar_file = request.files.get("avatar")
    if avatar_file and avatar_file.filename:
        if avatar_file.mimetype and avatar_file.mimetype.startswith("image/"):
            avatar_file.seek(0, 2)
            file_size = avatar_file.tell()
            avatar_file.seek(0)

            if file_size <= 5 * 1024 * 1024:
                profile.avatar_data = avatar_file.read()
                profile.avatar_mime = avatar_file.mimetype

    db.session.commit()
    return redirect(url_for("routes.profile"))


@bp.route("/profile/avatar")
@login_required
def profile_avatar():
    """Retourne l'avatar de l'utilisateur courant."""
    profile = UserProfile.query.filter_by(user_sub=current_user.sub).first()
    if not profile or not profile.avatar_data:
        abort(404)

    return Response(
        profile.avatar_data, mimetype=profile.avatar_mime or "image/jpeg"
    )


# ─────────── TÂCHES PLANIFIÉES ───────────
@bp.route("/scheduled")
@login_required
def scheduled_tasks():
    """Page de gestion des tâches planifiées."""
    tasks = (
        ScheduledTask.query.filter_by(user_sub=current_user.sub)
        .order_by(ScheduledTask.created_at.desc())
        .all()
    )
    return render_template("scheduled.html", tasks=tasks, modules=MODULES)


@bp.route("/scheduled/create", methods=["POST"])
@login_required
def create_scheduled_task():
    """Créer une nouvelle tâche planifiée."""
    name = request.form.get("name", "").strip()
    module_name = request.form.get("module_name", "").strip()
    target = request.form.get("target", "").strip()
    mode = request.form.get("mode", "quick")
    schedule_type = request.form.get("schedule_type", "daily")
    schedule_time_str = request.form.get("schedule_time", "09:00")
    schedule_day = request.form.get("schedule_day")

    if not name or not module_name:
        return redirect(url_for("routes.scheduled_tasks"))

    try:
        hour, minute = map(int, schedule_time_str.split(":"))
        schedule_time = time(hour, minute)
    except ValueError:
        schedule_time = time(9, 0)

    now = datetime.utcnow()
    next_run = _calculate_next_run(
        now, schedule_type, schedule_time, schedule_day
    )

    task = ScheduledTask(
        user_sub=current_user.sub,
        name=name,
        module_name=module_name,
        target=target or None,
        mode=mode,
        schedule_type=schedule_type,
        schedule_time=schedule_time,
        schedule_day=int(schedule_day) if schedule_day else None,
        next_run=next_run,
    )

    db.session.add(task)
    db.session.commit()
    return redirect(url_for("routes.scheduled_tasks"))


@bp.route("/scheduled/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_scheduled_task(task_id: int):
    """Activer/désactiver une tâche planifiée."""
    task = ScheduledTask.query.get_or_404(task_id)
    if task.user_sub != current_user.sub:
        abort(403)

    task.is_active = not task.is_active
    db.session.commit()
    return redirect(url_for("routes.scheduled_tasks"))


@bp.route("/scheduled/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_scheduled_task(task_id: int):
    """Supprimer une tâche planifiée."""
    task = ScheduledTask.query.get_or_404(task_id)
    if task.user_sub != current_user.sub:
        abort(403)

    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("routes.scheduled_tasks"))


def _calculate_next_run(
    now, schedule_type, schedule_time, schedule_day=None
):
    """Calcule la prochaine exécution d'une tâche."""
    next_date = now.date()

    if schedule_type == "daily":
        if now.time() >= schedule_time:
            next_date += timedelta(days=1)

    elif schedule_type == "weekly":
        target_weekday = int(schedule_day) if schedule_day else 0
        days_ahead = target_weekday - now.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        next_date += timedelta(days=days_ahead)

    elif schedule_type == "monthly":
        target_day = int(schedule_day) if schedule_day else 1
        if now.day <= target_day and now.time() < schedule_time:
            next_date = next_date.replace(day=target_day)
        else:
            if now.month == 12:
                next_date = next_date.replace(
                    year=now.year + 1, month=1, day=target_day
                )
            else:
                next_date = next_date.replace(
                    month=now.month + 1, day=target_day
                )

    return datetime.combine(next_date, schedule_time)


# ─────────── FLUX RSS VEILLE ───────────
@bp.route("/veille")
@login_required
def veille():
    feed = feedparser.parse("https://cyberveille.curated.co/issues.rss")
    articles: list[dict[str, Any]] = []

    for entry in feed.entries[:20]:
        published = entry.get("published", "")
        soup = BeautifulSoup(entry.summary, "html.parser")

        for h3 in soup.find_all("h3"):
            h3.decompose()

        hr = soup.find("hr")
        if hr:
            for sibling in hr.find_next_siblings():
                sibling.decompose()
            hr.decompose()

        for h4 in soup.find_all("h4"):
            a_tag = h4.find("a")
            if not a_tag:
                continue
            title = a_tag.get_text().strip()
            link = a_tag.get("href", "").strip()

            summary_html = ""
            summary_p = h4.find_next_sibling("p")
            if summary_p:
                summary_html = str(summary_p)

            source = ""
            if summary_p:
                source_p = summary_p.find_next_sibling("p")
                if source_p and source_p.find("a"):
                    source = source_p.get_text().strip()

            img_url = ""
            next_a = h4.find_next_sibling("a")
            if next_a and next_a.find("img"):
                img_tag = next_a.find("img")
                img_url = img_tag.get("src", "").strip()

            articles.append(
                {
                    "title": title,
                    "link": link,
                    "published": published,
                    "summary": summary_html,
                    "source": source,
                    "image_url": img_url,
                }
            )

    return render_template("veille.html", articles=articles)
