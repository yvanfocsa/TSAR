# web/app/tasks.py
from __future__ import annotations

import datetime
import json
import logging
import os
import re
import time

import docker
import requests
from celery import Celery
from celery.signals import worker_process_init

from .modules import MODULES, load_modules

logging.basicConfig(level=logging.INFO)

celery = Celery("tsar")


@worker_process_init.connect
def init_modules_on_worker_start(**kwargs):
    logging.info("Celery worker process starting, loading modules...")
    load_modules()
    logging.info(f"Modules loaded in worker: {[m['name'] for m in MODULES]}")


@celery.task(name="tsar.run_job")
def run_job(module_name: str, params: dict, user_sub: str) -> int | None:
    """Exécute un module et génère un rapport PDF."""
    from . import create_app, db
    from .models import Report
    from .pdf import generate_report
    from .pdf_crypto import encrypt

    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        logging.info(f"Début du job '{module_name}' pour l'utilisateur {user_sub}")

        mod = next((m for m in MODULES if m["name"] == module_name), None)
        if not mod:
            logging.error(f"FATAL: Module '{module_name}' introuvable dans le worker.")
            return None

        cmd = mod["cmd"](params)
        container_name = os.getenv("TOOLBOX_CONTAINER", "toolbox")
        try:
            client = docker.from_env()
            container = client.containers.get(container_name)
            exec_res = container.exec_run(cmd, stdout=True, stderr=True)
            output = exec_res.output.decode(errors="ignore")
            logging.info(f"Exécution de la commande pour '{module_name}' terminée.")
        except docker.errors.NotFound:
            output = f"ERREUR : Le conteneur Docker '{container_name}' est introuvable."
            logging.error(output)
        except Exception as exc:
            output = f"ERREUR : {exc!s}"
            logging.error(f"Erreur lors de l'exécution du job : {output}")

        try:
            pdf_bytes = generate_report(
                "stdout_report.html",
                {
                    "module": mod,
                    "params": params,
                    "output": output,
                    "date": datetime.datetime.utcnow(),
                },
            )

            cipher = encrypt(pdf_bytes)
            pdf_name = f"{module_name.replace(' ', '_')}_{datetime.datetime.utcnow():%Y%m%d%H%M}.pdf"

            report = Report(user_sub=user_sub, filename=pdf_name, pdf_data=cipher)

            db.session.add(report)
            db.session.commit()

            logging.info(f"Rapport #{report.id} ('{pdf_name}') sauvegardé avec succès.")
            return report.id

        except Exception as e:
            logging.error(
                f"Erreur lors de la génération ou sauvegarde du PDF : {e}",
                exc_info=True,
            )
            db.session.rollback()
            return None


@celery.task(name="tsar.check_scheduled_tasks")
def check_scheduled_tasks():
    """Vérifie et exécute les tâches planifiées dues."""
    from . import create_app, db
    from .models import ScheduledTask
    from .routes import _calculate_next_run

    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        now = datetime.datetime.utcnow()
        due_tasks = ScheduledTask.query.filter(
            ScheduledTask.is_active == True, ScheduledTask.next_run <= now
        ).all()

        logging.info(f"Vérification des tâches planifiées : {len(due_tasks)} tâche(s) due(s).")

        for task in due_tasks:
            logging.info(f"Exécution de la tâche planifiée #{task.id}: {task.name}")

            mod = next((m for m in MODULES if m["name"] == task.module_name), None)
            params = {"mode": task.mode}
            if mod and mod.get("schema"):
                main_param_name = mod["schema"][0].get("name", "target")
                params[main_param_name] = task.target
            else:
                params["target"] = task.target

            run_job.delay(task.module_name, params, task.user_sub)

            task.last_run = now
            task.next_run = _calculate_next_run(
                now, task.schedule_type, task.schedule_time, task.schedule_day
            )
            db.session.commit()
            logging.info(f"Tâche #{task.id} reprogrammée pour {task.next_run}.")

    return len(due_tasks)

def _decode_cvss_vector(vector_string: str) -> list[dict]:
    """Traduit et décode un vecteur CVSS v3.1 en une liste lisible."""
    if not vector_string or not vector_string.startswith("CVSS:3.1"):
        return []

    translations = {
        "AV": "Vecteur d'Attaque", "AC": "Complexité de l'Attaque", "PR": "Privilèges Requis",
        "UI": "Interaction Utilisateur", "S": "Scope", "C": "Confidentialité",
        "I": "Intégrité", "A": "Disponibilité",
        "N": "Réseau", "A": "Adjacent", "L": "Local", "P": "Physique",
        "H": "Haute", "L": "Faible",
        "N": "Aucun", "R": "Requise",
        "C": "Changé", "U": "Inchangé",
    }
    
    decoded = []
    parts = vector_string.split('/')
    for part in parts[1:]:
        key, value = part.split(':')
        metric_fr = translations.get(key, key)
        value_fr = translations.get(value, value)
        decoded.append({"metric": metric_fr, "value": value_fr})
        
    return decoded

@celery.task(name="tsar.run_cve_analysis", acks_late=True, throws=(Exception,))
def run_cve_analysis(cve_id: str) -> dict:
    """Interroge l'API NVD, décode et traduit les informations d'une CVE."""
    logging.info(f"Début de l'analyse API pour la CVE : {cve_id}")
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        response = requests.get(api_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        
        if not data.get("vulnerabilities"):
            raise Exception(f"La CVE '{cve_id}' n'a pas été trouvée dans la base de données NVD.")
            
        cve_data = data["vulnerabilities"][0]["cve"]
        description = next((d['value'] for d in cve_data.get('descriptions', []) if d['lang'] == 'en'), "Description non disponible.")
        
        cvss_metrics = cve_data.get("metrics", {})
        cvss_v3_data = cvss_metrics.get("cvssMetricV31", cvss_metrics.get("cvssMetricV30", [{}]))[0].get("cvssData", {})
        
        weaknesses = cve_data.get("weaknesses", [{}])[0].get("description", [{}])[0].get("value", "N/A")
        
        severity_map = {"CRITICAL": "CRITIQUE", "HIGH": "ÉLEVÉE", "MEDIUM": "MOYENNE", "LOW": "FAIBLE"}
        severity_fr = severity_map.get(cvss_v3_data.get("baseSeverity"), cvss_v3_data.get("baseSeverity"))

        result = {
            "id": cve_data.get("id"),
            "publishedDate": cve_data.get("published"),
            "lastModifiedDate": cve_data.get("lastModified"),
            "description": description,
            "cvss": {
                "score": cvss_v3_data.get("baseScore"),
                "severity": severity_fr,
                "vector": cvss_v3_data.get("vectorString"),
            },
            "decoded_vector": _decode_cvss_vector(cvss_v3_data.get("vectorString")),
            "cwe": weaknesses,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_data.get('id')}"
        }
        
        logging.info(f"Analyse API de {cve_id} réussie.")
        return result

    except requests.exceptions.RequestException as e:
        logging.error(f"Erreur de communication avec l'API NVD pour {cve_id}: {e}")
        raise Exception("Impossible de contacter le service d'analyse des vulnérabilités (NVD).")
    except Exception as e:
        logging.error(f"Erreur inattendue lors de l'analyse de {cve_id}: {e}", exc_info=True)
        raise

def _extract_components_from_report(report_text: str) -> set[str]:
    """Extrait des composants potentiels (produit + version) d'un rapport."""
    pattern = re.compile(r"([a-zA-Z0-9\._-]+)\s+version\s+([\d\.]+[a-z\d\.]*)", re.IGNORECASE)
    pattern_simple = re.compile(r"([a-zA-Z0-9\._-]+)/([\d\.]+[a-z\d\.]*)", re.IGNORECASE)
    
    found = set()
    for match in pattern.finditer(report_text):
        product = match.group(1).lower().replace("_", " ").replace("-", " ")
        version = match.group(2)
        found.add(f"{product} {version}")
        
    for match in pattern_simple.finditer(report_text):
        product = match.group(1).lower().replace("_", " ").replace("-", " ")
        version = match.group(2)
        found.add(f"{product} {version}")

    return {c for c in found if len(c.split()) > 1 and len(c.split()[1]) > 2}

@celery.task(name="tsar.run_inference_analysis", acks_late=True, throws=(Exception,))
def run_inference_analysis(report_id: int, user_sub: str) -> list[dict]:
    """Extrait les composants d'un rapport et interroge l'API NVD pour trouver des CVEs associées."""
    from . import create_app, db
    from .models import Report
    from .pdf_crypto import decrypt
    from pdfminer.high_level import extract_text
    import io

    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        logging.info(f"Lancement de l'analyse par API sur le rapport #{report_id}.")
        
        report = Report.query.get(report_id)
        if not report or report.user_sub != user_sub:
            raise Exception("Rapport non trouvé ou accès non autorisé.")

        pdf_bytes = decrypt(report.pdf_data)
        text = extract_text(io.BytesIO(pdf_bytes))

        components = _extract_components_from_report(text)
        if not components:
            return []

        logging.info(f"{len(components)} composants potentiels détectés: {', '.join(components)}")

        all_results = []
        for component in components:
            try:
                time.sleep(6) 
                
                api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(component)}&keywordExactMatch"
                response = requests.get(api_url, timeout=20)
                response.raise_for_status()
                data = response.json()

                if data.get("vulnerabilities"):
                    cves_found = [vuln["cve"]["id"] for vuln in data["vulnerabilities"]]
                    all_results.append({
                        "component": component,
                        "cves": cves_found,
                        "count": len(cves_found)
                    })
            except requests.exceptions.RequestException as e:
                logging.warning(f"Erreur API pour le composant '{component}': {e}")
                continue
        
        return all_results
