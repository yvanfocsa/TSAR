"""
Routes principaux : dashboard, exécution de modules, génération + téléchargement
de rapports et flux RSS.

Stack 100 % locale (pas d'IA) + Celery :
  • aucune importation directe de .tasks (évite les boucles)
  • appel asynchrone via current_app.celery.send_task(...)
"""

from __future__ import annotations

import io
import json
import re
import socket
import time as pytime
import zipfile
from collections import defaultdict
from datetime import datetime, time, timedelta
from io import BytesIO
from typing import Any

import feedparser
import psutil
import requests
import pytz
from bs4 import BeautifulSoup
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
from redis import Redis
from sqlalchemy import Date, cast, func
from werkzeug.utils import secure_filename

from . import db
from .models import (
    Project,
    ProjectFile,
    Report,
    ScanLog,
    ScheduledTask,
    UserProfile,
    Vulnerability,
)
# MODIFIÉ : Utiliser l'importation de l'objet modules pour accéder aux modules
from . import modules as modules_loader
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


def _extract_severities_from_text(text: str) -> list[str]:
    """Extrait les niveaux de sévérité (ex: [high]) d'un texte."""
    pattern = r"\[(critical|high|medium|low|info)\]"
    return re.findall(pattern, text, re.IGNORECASE)


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


@bp.route("/metrics/dashboard-charts")
@login_required
def dashboard_charts_json():
    """Fournit les données pour les graphiques du dashboard."""
    # 1. Top 5 des modules utilisés
    top_modules = (
        db.session.query(ScanLog.module, func.count(ScanLog.id).label("count"))
        .filter(ScanLog.user_sub == current_user.sub)
        .group_by(ScanLog.module)
        .order_by(func.count(ScanLog.id).desc())
        .limit(5)
        .all()
    )

    # 2. Répartition par catégorie
    module_to_category = {m["name"]: m["category"] for m in current_app.modules_obj.MODULES}
    all_scans = ScanLog.query.filter_by(user_sub=current_user.sub).all()
    category_counts = {}
    for scan in all_scans:
        category = module_to_category.get(scan.module, "Inconnue")
        category_counts[category] = category_counts.get(category, 0) + 1

    # 3. Scans par jour (7 derniers jours)
    seven_days_ago = datetime.utcnow() - timedelta(days=6)
    scans_by_day = (
        db.session.query(
            cast(ScanLog.created_at, Date).label("date"),
            func.count(ScanLog.id).label("count"),
        )
        .filter(
            ScanLog.user_sub == current_user.sub,
            ScanLog.created_at >= seven_days_ago.date(),
        )
        .group_by("date")
        .order_by("date")
        .all()
    )

    # Formater les données pour le graphique linéaire
    date_map = {
        (seven_days_ago + timedelta(days=i)).strftime("%Y-%m-%d"): 0
        for i in range(7)
    }
    for day in scans_by_day:
        date_map[day.date.strftime("%Y-%m-%d")] = day.count

    return jsonify({
        "top_modules": {"labels": [m[0] for m in top_modules], "data": [m[1] for m in top_modules]},
        "category_distribution": {"labels": list(category_counts.keys()), "data": list(category_counts.values())},
        "daily_activity": {"labels": list(date_map.keys()), "data": list(date_map.values())},
    })


# ─────────── DASHBOARD & CORE PAGES ───────────
@bp.route("/")
@login_required
def index():
    pub_ip, priv_ip = _get_ips()
    metrics = {"IP publique": pub_ip, "IP privée": priv_ip}
    favoris = [m for m in current_app.modules_obj.MODULES if m["name"] in session.get("favorites", [])]
    logs = (
        ScanLog.query.filter_by(user_sub=current_user.sub)
        .order_by(ScanLog.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template("dashboard.html", metrics=metrics, favoris=favoris, logs=logs)


@bp.route("/modules")
@login_required
def modules_home():
    cats = current_app.modules_obj.get_categories()
    category_order = [
        "Scans Complets",
        "Scan Réseau",
        "Web",
        "Active Directory",
        "Wordpress",
        "OSINT",
        "Reporting" # Ajout de la catégorie Reporting pour le générateur
    ]
    sorted_cats = dict(
        sorted(
            cats.items(),
            key=lambda item: category_order.index(item[0])
            if item[0] in category_order
            else len(category_order),
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
    mod = current_app.modules_obj.get_module_by_name(name)
    if not mod:
        abort(404)

    recent_scans = (
        ScanLog.query.filter(ScanLog.user_sub == current_user.sub)
        .order_by(ScanLog.created_at.desc())
        .limit(20)
        .all()
    )
    unique_targets_ordered = []
    seen_targets = set()
    for scan in recent_scans:
        if scan.target and scan.target not in seen_targets:
            unique_targets_ordered.append(scan.target)
            seen_targets.add(scan.target)
    recent_targets = unique_targets_ordered[:5]

    # MODIFIÉ : Logique pour le pivot
    pivot_public_url = None
    detected_ip = None
    if name == "Pivot & Audit Réseau Interne":
        # On récupère l'URL dédiée au pivot depuis la config
        pivot_public_url = current_app.config.get("PIVOT_PUBLIC_URL")
        
        # On essaie toujours de détecter l'IP publique comme alternative
        try:
            detected_ip = requests.get("https://api.ipify.org", timeout=2).text
        except requests.RequestException:
            detected_ip = "Détection échouée"


    return render_template(
        "module_launcher.html",
        mod=mod,
        pivot_public_url=pivot_public_url,
        detected_ip=detected_ip,
        recent_targets=recent_targets,
    )


@bp.route("/modules/<name>/run", methods=["POST"])
@login_required
def module_run(name: str):
    mod = current_app.modules_obj.get_module_by_name(name)
    if not mod:
        abort(404)

    is_grouped_schema = (
        mod.get("schema") and mod["schema"][0].get("group_name") is not None
    )
    # MODIFIÉ : Récupération correcte des paramètres de formulaire, surtout pour les multiselect
    params = {}
    if is_grouped_schema:
        for group_data in mod.get("schema", []): # Renommé 'group' en 'group_data' pour éviter le shadowing
            for field in group_data.get("fields", []):
                if field.get("type") == "multiselect":
                    params[field["name"]] = request.form.getlist(field["name"])
                else:
                    params[field["name"]] = request.form.get(field["name"], "")
    else:
        for field in mod.get("schema", []):
            if field.get("type") == "multiselect":
                params[field["name"]] = request.form.getlist(field["name"])
            else:
                params[field["name"]] = request.form.get(field["name"], "")

    if name == "Pivot & Audit Réseau Interne" and params.get("action") == "generate_config":
        async_result = current_app.celery.send_task(
            "app.tasks.run_job", args=[name, params, current_user.sub]
        )
        result = async_result.get(timeout=30) 
        return jsonify(result)

    job = current_app.celery.send_task(
        "app.tasks.run_job", args=[name, params, current_user.sub]
    )
    return jsonify({"job_id": job.id})


@bp.route("/job/stream/<job_id>")
@login_required
def job_stream(job_id: str):
    redis_client = Redis.from_url(current_app.config["CELERY_BROKER_URL"])
    pubsub = redis_client.pubsub()
    channel = f"job_log_stream:{job_id}"
    pubsub.subscribe(channel)

    def generate():
        try:
            for message in pubsub.listen():
                if message["type"] == "message":
                    data = message["data"].decode("utf-8")
                    if data == "__END_OF_STREAM__":
                        yield f"data: {json.dumps({'event': 'end'})}\n\n"
                        break
                    else:
                        yield f"data: {json.dumps({'log': data})}\n\n"
                pytime.sleep(0.01)
        except GeneratorExit:
            pass
        finally:
            pubsub.unsubscribe(channel)
            pubsub.close()

    return Response(generate(), mimetype="text/event-stream")


@bp.route("/job/cancel/<job_id>", methods=["POST"])
@login_required
def job_cancel(job_id: str):
    try:
        current_app.celery.control.revoke(job_id, terminate=True, signal="SIGKILL")
        return jsonify({"status": "success", "message": "Demande d'annulation envoyée."})
    except Exception as e:
        current_app.logger.error(f"Erreur lors de l'annulation du job {job_id}: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@bp.route("/job/status/<job_id>")
@login_required
def job_status(job_id: str):
    from celery.result import AsyncResult

    task = AsyncResult(job_id, app=current_app.celery)
    response = {
        "state": task.state,
        "result": task.result if task.state == "SUCCESS" else None,
    }
    if task.state == "FAILURE":
        response["error"] = str(task.info)
    elif task.state == "REVOKED":
        response["result"] = {"status": "revoked"}
    return jsonify(response)


@bp.route("/vpn/config/<token>")
# Le décorateur @login_required a été retiré ici pour permettre le téléchargement non authentifié via un token éphémère.
def download_vpn_config(token: str):
    try:
        redis_client = Redis.from_url(current_app.config["CELERY_BROKER_URL"])
        redis_key = f"vpn_config:{token}"
        config_data = redis_client.getdel(redis_key)
        if not config_data:
            abort(404, "Configuration non trouvée ou déjà utilisée.")
        return Response(
            config_data,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=wg0.conf"},
        )
    except Exception as e:
        current_app.logger.error(
            f"Erreur lors du téléchargement de la config VPN: {e}"
        )
        abort(500)


@bp.route("/vpn/script/<token>")
# Le décorateur @login_required a été retiré ici pour permettre le téléchargement non authentifié via un token éphémère.
def download_vpn_script(token: str):
    try:
        redis_client = Redis.from_url(current_app.config["CELERY_BROKER_URL"])
        redis_key = f"vpn_script:{token}"
        script_data = redis_client.getdel(redis_key)
        if not script_data:
            abort(404, "Script non trouvé ou déjà utilisé.")
        return Response(script_data, mimetype="text/x-shellscript")
    except Exception as e:
        current_app.logger.error(
            f"Erreur lors du téléchargement du script VPN: {e}"
        )
        abort(500)


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
        f'<button hx-post="{url_for("routes.toggle_favorite", name=name)}" hx-swap="outerHTML" class="fav-btn text-2xl">{star}</button>',
        200,
        {"Content-Type": "text/html"},
    )


# ─────────── PDF REPORTS & COMPARISON ───────────
def extract_ports(text):
    return re.findall(r"^\s*(\d+/(?:tcp|udp))\s+open", text, re.MULTILINE)


def extract_vulnerabilities(text):
    cves = re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    nuclei_vulns = re.findall(
        r"\[(.*?)\].*?\[(critical|high|medium|low|info)\].*?http", text
    )
    result = [c.upper() for c in cves]
    result.extend([f"{vuln.strip()} ({sev})" for vuln, sev in nuclei_vulns])
    return list(set(result))

@bp.route("/reports/<int:rid>/<report_format>", methods=["GET"])
@login_required
def get_report_formatted(rid: int, report_format: str):
    rep = Report.query.get_or_404(rid)
    if rep.user_sub != current_user.sub:
        abort(403)

    base_filename = rep.filename.replace('.pdf', '')

    try:
        pdf_bytes = decrypt(rep.pdf_data)
        report_text = extract_text(BytesIO(pdf_bytes))
    except Exception as e:
        current_app.logger.error(f"Erreur de déchiffrement ou d'extraction pour rapport {rid}: {e}")
        abort(500, description="Erreur lors de l'accès au rapport chiffré.")

    if report_format == 'pdf':
        return send_file(
            BytesIO(pdf_bytes),
            as_attachment=False, 
            download_name=f"{base_filename}.pdf",
            mimetype="application/pdf"
        )
    elif report_format == 'download_pdf': 
        return send_file(
            BytesIO(pdf_bytes),
            as_attachment=True, 
            download_name=f"{base_filename}.pdf",
            mimetype="application/pdf"
        )
    elif report_format == 'html':
        html_content = f"<!DOCTYPE html><html><head><title>{rep.filename}</title><style>body {{ font-family: monospace; white-space: pre-wrap; }}</style></head><body><pre>{report_text}</pre></body></html>"
        return Response(html_content, mimetype="text/html")
    elif report_format == 'txt':
        return send_file(
            BytesIO(report_text.encode('utf-8')),
            as_attachment=True,
            download_name=f"{base_filename}.txt",
            mimetype="text/plain"
        )
    else:
        abort(404, description="Format de rapport non supporté.")

@bp.route("/reports/<int:rid>")
@login_required
def view_report_default(rid: int):
    return redirect(url_for('routes.get_report_formatted', rid=rid, report_format='pdf'))


@bp.route("/reports/<int:rid>/delete", methods=["POST"])
@login_required
def delete_report(rid: int):
    rep = Report.query.get_or_404(rid)
    if rep.user_sub != current_user.sub:
        abort(403)
    project_id_to_redirect = rep.project_id
    db.session.delete(rep)
    db.session.commit()
    if project_id_to_redirect:
        return redirect(
            url_for("routes.project_detail", project_id=project_id_to_redirect)
        )
    return redirect(url_for("routes.index")) 


# ─────────── CVE & COMPONENT ANALYSIS ───────────
@bp.route("/cve-analysis", methods=["GET", "POST"])
@login_required
def cve_analysis():
    reports_for_dropdown = (
        Report.query.filter_by(user_sub=current_user.sub)
        .order_by(Report.created_at.desc())
        .all()
    )

    if request.method == "POST":
        job = None
        analysis_target = None
        if "cve_id" in request.form and request.form["cve_id"]:
            cve_id = request.form.get("cve_id", "").strip()
            job = current_app.celery.send_task(
                "app.tasks.run_cve_analysis", args=[cve_id]
            )
            analysis_target = cve_id
        elif "report_id" in request.form and request.form["report_id"]:
            report_id = int(request.form["report_id"])
            report = Report.query.get_or_404(report_id)
            if report.user_sub != current_user.sub:
                abort(403)
            
            pdf_bytes = decrypt(report.pdf_data)
            text = extract_text(io.BytesIO(pdf_bytes))

            job = current_app.celery.send_task(
                "app.tasks.analyze_report_for_vulns",
                args=[report_id, text],
            )
            analysis_target = f"Rapport: {report.filename}"
        else:
            return render_template(
                "cve_analysis.html",
                reports=reports_for_dropdown, 
                error="Veuillez fournir un ID de CVE ou sélectionner un rapport.",
            )
        return render_template(
            "cve_analysis.html",
            reports=reports_for_dropdown, 
            job_id=job.id,
            analysis_target=analysis_target,
        )
    return render_template("cve_analysis.html", reports=reports_for_dropdown)


# ─────────── PROFIL UTILISATEUR ───────────
@bp.route("/profile")
@login_required
def profile():
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
    profile = UserProfile.query.filter_by(user_sub=current_user.sub).first()
    if not profile or not profile.avatar_data:
        abort(404)
    return Response(profile.avatar_data, mimetype=profile.avatar_mime or "image/jpeg")


# ─────────── TÂCHES PLANIFIÉES ───────────
@bp.route("/scheduled")
@login_required
def scheduled_tasks():
    tasks = (
        ScheduledTask.query.filter_by(user_sub=current_user.sub)
        .order_by(ScheduledTask.created_at.desc())
        .all()
    )
    return render_template("scheduled.html", tasks=tasks, modules=current_app.modules_obj.MODULES) 


@bp.route("/scheduled/create", methods=["POST"])
@login_required
def create_scheduled_task():
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
    task = ScheduledTask(
        user_sub=current_user.sub,
        name=name,
        module_name=module_name,
        target=target or None,
        mode=mode,
        schedule_type=schedule_type,
        schedule_time=schedule_time,
        schedule_day=int(schedule_day) if schedule_day else None,
    )
    task.next_run = task.calculate_next_run()
    db.session.add(task)
    db.session.commit()
    return redirect(url_for("routes.scheduled_tasks"))


@bp.route("/scheduled/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle_scheduled_task(task_id: int):
    task = ScheduledTask.query.get_or_404(task_id)
    if task.user_sub != current_user.sub:
        abort(403)
    task.is_active = not task.is_active
    db.session.commit()
    return redirect(url_for("routes.scheduled_tasks"))


@bp.route("/scheduled/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_scheduled_task(task_id: int):
    task = ScheduledTask.query.get_or_404(task_id)
    if task.user_sub != current_user.sub:
        abort(403)
    db.session.delete(task)
    db.session.commit()
    return redirect(url_for("routes.scheduled_tasks"))


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


# ─────────── PROJETS ───────────
@bp.route("/projects")
@login_required
def projects_list():
    """Affiche la liste de tous les projets de l'utilisateur."""
    user_projects = (
        Project.query.filter_by(user_sub=current_user.sub)
        .order_by(Project.created_at.desc())
        .all()
    )
    return render_template("projects.html", projects=user_projects)


@bp.route("/projects/create", methods=["POST"])
@login_required
def create_project():
    """Crée un nouveau projet."""
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if name:
        new_project = Project(
            user_sub=current_user.sub, name=name, description=description
        )
        db.session.add(new_project)
        db.session.commit()
    return redirect(url_for("routes.projects_list"))


@bp.route("/project/<int:project_id>")
@login_required
def project_detail(project_id: int):
    """Affiche la page de détail d'un projet avec ses rapports et fichiers."""
    project = Project.query.get_or_404(project_id)
    if project.user_sub != current_user.sub:
        abort(403)
    
    vulnerabilities = (
        Vulnerability.query.join(Report)
        .filter(Report.project_id == project.id, Vulnerability.user_sub == current_user.sub)
        .order_by(Vulnerability.cvss_score.desc().nullslast(), Vulnerability.found_at.desc())
        .all()
    )

    mod_report_generator = current_app.modules_obj.get_module_by_name("Générateur de Rapport de Synthèse")
    report_sections_choices = current_app.modules_obj.get_reporting_sections_choices()

    return render_template("project_detail.html", 
        project=project, 
        vulnerabilities=vulnerabilities,
        mod_report_generator=mod_report_generator,
        report_sections_choices=report_sections_choices
    )


@bp.route("/project/<int:project_id>/stats")
@login_required
def project_stats(project_id: int):
    """Fournit les données pour le dashboard d'un projet."""
    project = Project.query.get_or_404(project_id)
    if project.user_sub != current_user.sub:
        abort(403)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    vulns = (
        Vulnerability.query.join(Report)
        .filter(Report.project_id == project.id)
        .all()
    )
    for vuln in vulns:
        sev = vuln.severity or "UNKNOWN"
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["UNKNOWN"] += 1

    timeline_events = []
    scans = ScanLog.query.filter_by(project_id=project.id).all()
    uploads = ProjectFile.query.filter_by(project_id=project.id).all()

    paris_tz = pytz.timezone('Europe/Paris')

    for scan in scans:
        paris_dt = scan.created_at.replace(tzinfo=pytz.utc).astimezone(paris_tz)
        timeline_events.append({
            "type": "scan",
            "date": paris_dt.isoformat(),
            "details": f"Scan '{scan.module}' ({scan.mode}) sur {scan.target or 'cible non spécifiée'}"
        })
    for upload in uploads:
        paris_dt = upload.uploaded_at.replace(tzinfo=pytz.utc).astimezone(paris_tz)
        timeline_events.append({
            "type": "upload",
            "date": paris_dt.isoformat(),
            "details": f"Fichier '{upload.filename}' uploadé"
        })

    timeline_events.sort(key=lambda x: x["date"], reverse=True)

    return jsonify({
        "severity_chart": {
            "labels": [k.capitalize() for k in severity_counts.keys()],
            "data": list(severity_counts.values())
        },
        "timeline": timeline_events[:15]
    })


@bp.route("/project/<int:project_id>/upload", methods=["POST"])
@login_required
def upload_to_project(project_id: int):
    """Upload un fichier dans un projet."""
    project = Project.query.get_or_404(project_id)
    if project.user_sub != current_user.sub:
        abort(403)
    file = request.files.get("file")
    if file and file.filename:
        new_file = ProjectFile(
            project_id=project.id,
            user_sub=current_user.sub,
            filename=file.filename,
            file_data=file.read(),
            mime_type=file.mimetype,
        )
        db.session.add(new_file)
        db.session.commit()
    return redirect(url_for("routes.project_detail", project_id=project_id))


@bp.route("/project/file/<int:file_id>")
@login_required
def download_project_file(file_id: int):
    """Télécharge un fichier de projet."""
    file = ProjectFile.query.get_or_404(file_id)
    if file.user_sub != current_user.sub:
        abort(403)
    return send_file(
        BytesIO(file.file_data),
        as_attachment=True,
        download_name=file.filename,
        mimetype=file.mime_type,
    )


@bp.route("/project/<int:project_id>/export")
@login_required
def export_project(project_id: int):
    """Exporte tous les rapports et fichiers d'un projet dans une archive ZIP."""
    project = Project.query.get_or_404(project_id)
    if project.user_sub != current_user.sub:
        abort(403)
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
        reports_folder = "Rapports_Scans/"
        for report in project.reports:
            try:
                pdf_data = decrypt(report.pdf_data)
                zf.writestr(f"{reports_folder}{report.filename}", pdf_data)
            except Exception as e:
                current_app.logger.error(
                    f"Impossible de déchiffrer le rapport {report.id} pour l'export: {e}"
                )
                zf.writestr(
                    f"{reports_folder}{report.filename}.erreur.txt",
                    f"Erreur lors du déchiffrement: {e}",
                )
        files_folder = "Documents_Uploades/"
        for file in project.files:
            zf.writestr(f"{files_folder}{file.filename}", file.file_data)
        project_info = f"""
Projet: {project.name}
Description: {project.description}
Date de création: {project.created_at.strftime('%Y-%m-%d %H:%M:%S')}
Exporté le: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}
"""
        zf.writestr("info_projet.txt", project_info)
    memory_file.seek(0)
    safe_filename = secure_filename(project.name).replace(" ", "_")
    download_name = f"projet_{safe_filename}_export.zip"
    return send_file(
        memory_file,
        download_name=download_name,
        as_attachment=True,
        mimetype="application/zip",
    )


@bp.route("/project/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id: int):
    """Supprime un projet et toutes ses données associées."""
    project = Project.query.get_or_404(project_id)
    if project.user_sub != current_user.sub:
        abort(403)
    db.session.delete(project)
    db.session.commit()
    return redirect(url_for("routes.projects_list"))