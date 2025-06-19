# web/app/tasks.py
from __future__ import annotations

import datetime
import logging
import os
import re
import shlex
import time
import uuid

import docker
import requests
from celery import Celery, group, chain, signature
from celery.signals import worker_process_init
from redis import Redis

from . import create_app, db
from .models import Project, Report, ScanLog, ScheduledTask, Vulnerability
from . import modules as modules_loader
from .pdf import generate_report
from .pdf_crypto import encrypt

logging.basicConfig(level=logging.INFO) # Assure un niveau de log INFO pour voir les messages


celery = Celery('tasks', broker='redis://redis:6379/0')


@worker_process_init.connect
def init_modules_on_worker_start(**kwargs):
    logging.info("Celery worker process starting, loading modules...")
    modules_loader.load_modules()
    logging.info(f"Modules loaded in worker: {[m['name'] for m in modules_loader.MODULES]}")


def _generate_vpn_config(public_ip: str, client_lan_cidr: str | None) -> tuple[str, str]:
    """Génère les configurations serveur et client pour WireGuard."""
    logging.info(f"[DEBUG_VPN_GEN_FUNC] _generate_vpn_config received client_lan_cidr: '{client_lan_cidr}'") # NOUVEAU LOG

    client = docker.from_env()
    container = client.containers.get(os.getenv("TOOLBOX_CONTAINER", "toolbox"))

    # Génération des clés serveur
    _, server_priv_key_b = container.exec_run("wg genkey")
    server_priv_key = server_priv_key_b.decode().strip()
    _, server_pub_key_b = container.exec_run(f"bash -c \"echo '{server_priv_key}' | wg pubkey\"")
    server_pub_key = server_pub_key_b.decode().strip()

    # Génération des clés client
    _, client_priv_key_b = container.exec_run("wg genkey")
    client_priv_key = client_priv_key_b.decode().strip()
    _, client_pub_key_b = container.exec_run(f"bash -c \"echo '{client_priv_key}' | wg pubkey\"")
    client_pub_key = client_pub_key_b.decode().strip()

    # On nettoie l'IP/hostname pour retirer le protocole (http/https)
    endpoint_host = public_ip.replace("https://", "").replace("http://", "").split('/')[0]

    server_allowed_ips = "10.0.0.2/32"
    if client_lan_cidr and client_lan_cidr.strip(): # S'assurer qu'il n'est pas vide
        server_allowed_ips += f", {client_lan_cidr.strip()}" # <-- ICI ÇA DOIT ÊTRE BON
        logging.info(f"[DEBUG_VPN_GEN_FUNC] Appending client_lan_cidr to AllowedIPs: '{client_lan_cidr.strip()}'. Final AllowedIPs: {server_allowed_ips}") # NOUVEAU LOG
    else:
        logging.info(f"[DEBUG_VPN_GEN_FUNC] client_lan_cidr was empty or None. AllowedIPs remains: {server_allowed_ips}") # NOUVEAU LOG


    server_conf = f"""[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = {server_priv_key}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = {client_pub_key}
AllowedIPs = {server_allowed_ips}
"""
    client_conf = f"""[Interface]
PrivateKey = {client_priv_key}
Address = 10.0.0.2/24

[Peer]
PublicKey = {server_pub_key}
Endpoint = {shlex.quote(endpoint_host)}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
    return server_conf, client_conf


@celery.task(bind=True)
def run_job(self, module_name: str, params: dict, user_sub: str) -> dict:
    """
    Exécute un module.
    Cherche ou crée automatiquement un projet basé sur la cible du scan.
    Streame les logs vers Redis Pub/Sub.
    """
    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        job_id = self.request.id
        redis_client = Redis.from_url(app.config["CELERY_BROKER_URL"])
        stream_channel = f"job_log_stream:{job_id}"

        logging.info(f"Début du job '{module_name}' (ID: {job_id}) pour l'utilisateur {user_sub}")

        mod = modules_loader.get_module_by_name(module_name)
        if not mod:
            logging.error(f"FATAL: Module '{module_name}' introuvable.")
            return {"error": f"Module '{module_name}' introuvable."}

        if module_name == "Pivot & Audit Réseau Interne" and params.get("action") == "generate_config":
            try:
                public_ip = params.get("public_ip", "VOTRE_IP_PUBLIQUE")
                target_os = params.get("target_os", "Linux")
                client_lan_cidr = params.get("client_lan_cidr") # <-- Récupère le paramètre du formulaire
                logging.info(f"[DEBUG_VPN_GEN] run_job received client_lan_cidr from params: '{client_lan_cidr}'") # NOUVEAU LOG
                base_url = app.config.get("APP_BASE_URL", "http://localhost:5373")

                if not public_ip or public_ip == "VOTRE_IP_PUBLIQUE":
                    return {"error": "L'IP publique est requise pour générer la configuration."}

                server_conf, client_conf = _generate_vpn_config(public_ip, client_lan_cidr) # Passe le paramètre

                client = docker.from_env()
                container = client.containers.get(os.getenv("TOOLBOX_CONTAINER", "toolbox"))
                container.exec_run(f"bash -c 'echo \"{server_conf}\" > /etc/wireguard/wg0.conf && chmod 600 /etc/wireguard/wg0.conf'")

                config_token = str(uuid.uuid4())
                redis_client.set(f"vpn_config:{config_token}", client_conf, ex=300)
                config_url = f"{base_url}/vpn/config/{config_token}"

                if target_os == "Linux":
                    script_content = f"""#!/bin/bash
echo "[+] Création du dossier de configuration si nécessaire..."
mkdir -p /etc/wireguard
echo "[+] Téléchargement de la configuration VPN..."
curl -sSL "{config_url}" -o /etc/wireguard/wg0.conf
if [ $? -ne 0 ]; then
    echo "[!] Erreur: Impossible de télécharger la configuration."
    exit 1
fi
echo "[+] Configuration sauvegardée dans /etc/wireguard/wg0.conf"
echo "[+] Définition des permissions..."
chmod 600 /etc/wireguard/wg0.conf
echo "[+] Activation du tunnel VPN (wg0)..."
wg-quick up wg0
if [ $? -eq 0 ]; then
    echo "[+] Le tunnel VPN est maintenant ACTIF."
    echo ""
    echo "[i] Détection du réseau local..."
    DETECTED_RANGE=$(ip -o -4 addr show | grep -v '127.0.0.1' | grep -v 'docker' | grep -v 'veth' | grep -v 'wg0' | awk '{{print $4}}' | head -n1)
    if [ -n "$DETECTED_RANGE" ]; then
        echo "[i] Réseau local principal détecté : $DETECTED_RANGE"
        echo "[i] Vous pouvez maintenant lancer un audit sur cette plage depuis l'interface TSAR."
    else
        echo "[!] Impossible de détecter automatiquement le réseau local."
    fi
else
    echo "[!] Erreur lors de l'activation du tunnel. Vérifiez que WireGuard est installé."
fi
"""
                    script_token = str(uuid.uuid4())
                    redis_client.set(f"vpn_script:{script_token}", script_content, ex=300)
                    script_url = f"{base_url}/vpn/script/{script_token}"

                    one_liner = f"curl -sSL {script_url} | sudo bash"
                    logging.info(f"Script d'install VPN Linux généré. Token: {script_token}")
                    return {"os": "linux", "one_liner": one_liner}

                elif target_os == "Windows":
                    logging.info(f"Lien de config VPN Windows généré. Token: {config_token}")
                    return {"os": "windows", "config_url": config_url}

            except Exception as e:
                logging.error(f"Erreur de génération VPN: {e}", exc_info=True)
                return {"error": str(e)}

        project = None
        target_name = params.get('target') or params.get('url') or params.get('github_target') or params.get('username')

        if target_name:
            project = Project.query.filter_by(name=target_name, user_sub=user_sub).first()
            if not project:
                logging.info(f"Projet '{target_name}' non trouvé. Création d'un nouveau projet.")
                project = Project(
                    name=target_name,
                    user_sub=user_sub,
                    description=f"Projet généré automatiquement pour la cible : {target_name}"
                )
                db.session.add(project)
                db.session.flush()

        cmd = mod["cmd"](params)

        logging.info(f"[DEBUG-CMD] Commande finale calculée pour '{module_name}': {cmd}")
        if len(cmd) > 2 and cmd[0] == 'bash' and cmd[1] == '-c':
            logging.info(f"[DEBUG-CMD] Contenu du script bash (-c) pour '{module_name}':\n---DEBUT SCRIPT---\n{cmd[2]}\n---FIN SCRIPT---")


        container_name = os.getenv("TOOLBOX_CONTAINER", "toolbox")
        full_output = []

        try:
            client = docker.from_env()
            container = client.containers.get(container_name)

            logging.info(f"[DEBUG-EXEC] Tentative d'exécution dans le conteneur '{container_name}'...")
            result = container.exec_run(cmd, stream=True, demux=True)
            logging.info(f"[DEBUG-EXEC] Commande envoyée au conteneur. Début du streaming de la sortie pour le job {job_id}...")

            for stdout_chunk, stderr_chunk in result.output:
                if stdout_chunk:
                    line = stdout_chunk.decode(errors="ignore")
                    full_output.append(line)
                    redis_client.publish(stream_channel, line)
                if stderr_chunk:
                    line = stderr_chunk.decode(errors="ignore")
                    full_output.append(line)
                    redis_client.publish(stream_channel, line)
            logging.info(f"[DEBUG-EXEC] Fin du streaming de la sortie pour le job {job_id}.")

        except docker.errors.NotFound:
            output = f"ERREUR : Le conteneur Docker '{container_name}' est introuvable."
            full_output.append(output)
            redis_client.publish(stream_channel, output)
            logging.error(output)
            return {"error": output}
        except Exception as exc:
            output = f"ERREUR lors de l'exécution de la commande dans le conteneur ou du traitement de la sortie : {exc!s}"
            full_output.append(output)
            redis_client.publish(stream_channel, output)
            logging.exception(output)
            return {"error": output}

        finally:
            redis_client.publish(stream_channel, "__END_OF_STREAM__")
            output_str = "".join(full_output)

            try:
                now = datetime.datetime.utcnow()
                context = {
                    "module": mod,
                    "params": params,
                    "output": output_str,
                    "date": now,
                    "target": target_name,
                    "vulnerabilities": [],
                    "project": project
                }

                pdf_bytes = generate_report("stdout_report.html", context)
                cipher = encrypt(pdf_bytes)
                pdf_name = f"{module_name.replace(' ', '_')}_{now:%Y%m%d%H%M}.pdf"

                report = Report(
                    user_sub=user_sub,
                    filename=pdf_name,
                    pdf_data=cipher,
                    project_id=project.id if project else None
                )

                db.session.add(report)
                project_id_for_analysis = project.id if project else None
                user_sub_for_analysis = user_sub

                db.session.commit()
                logging.info(f"Rapport #{report.id} ('{pdf_name}') sauvegardé pour le job {job_id}.")

                if module_name != "Générateur de Rapport de Synthèse":
                    workflow = chain(
                        analyze_report_for_vulns.s(report.id, output_str),
                        process_enrichment_and_synthesis.s(
                            report.id, project_id_for_analysis, user_sub_for_analysis
                        )
                    )
                    workflow.delay()
                    logging.info(f"Workflow d'analyse post-scan lancé pour rapport #{report.id}.")
                else:
                    logging.info(f"Rapport de synthèse généré #{report.id} pour le job {job_id}. Fin du traitement.")


                return {"report_id": report.id, "project_id": project_id_for_analysis}
            except Exception as e:
                logging.error(f"Erreur PDF pour le job {job_id}: {e}", exc_info=True)
                db.session.rollback()
                return {"error": "Erreur lors de la génération du rapport PDF."}


@celery.task(acks_late=True)
def process_enrichment_and_synthesis(vuln_ids_from_analysis: list[int], report_id: int, project_id: int | None, user_sub: str):
    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        logging.info(f"Début de process_enrichment_and_synthesis pour rapport #{report_id} (projet {project_id}).")

        if not vuln_ids_from_analysis:
            logging.info(f"Aucune vulnérabilité à enrichir pour le rapport #{report_id}. Fin de l'orchestration.")
            return

        enrichment_signatures = [enrich_vulnerability_details.s(v_id) for v_id in vuln_ids_from_analysis]

        project = Project.query.get(project_id)
        project_name = project.name if project else "N/A_Project"

        reporting_mod = modules_loader.get_module_by_name("Générateur de Rapport de Synthèse")
        if not reporting_mod:
            logging.error("Module 'Générateur de Rapport de Synthèse' introuvable. Impossible de générer de rapport de synthèse.")
            return

        synthesis_params = {'target': project_name}
        synthesis_params['sections'] = modules_loader.get_reporting_sections_choices_as_values()

        workflow_part2 = chain(
            group(enrichment_signatures),
            run_job.s(reporting_mod['name'], synthesis_params, user_sub)
        )
        workflow_part2.delay()

        logging.info(f"Partie 2 du workflow (enrichissement + synthèse) lancée pour rapport #{report.id}.")


@celery.task
def check_scheduled_tasks():
    """Vérifie et exécute les tâches planifiées dues."""
    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        now = datetime.datetime.utcnow()
        due_tasks = ScheduledTask.query.filter(
            ScheduledTask.is_active == True, ScheduledTask.next_run <= now
        ).all()

        logging.info(f"Vérification des tâches planifiées : {len(due_tasks)} tâche(s) due(s).")

        for task in due_tasks:
            logging.info(f"Exécution de la tâche planifiée #{task.id}: {task.name}")

            mod = modules_loader.get_module_by_name(task.module_name)
            params = {"mode": task.mode}
            if mod and mod.get("schema"):
                if mod["schema"][0].get("group_name"):
                    main_param_name = mod["schema"][0]["fields"][0].get("name", "target")
                else:
                    main_param_name = mod["schema"][0].get("name", "target")
                params[main_param_name] = task.target
            else:
                params["target"] = task.target

            run_job.delay(task.module_name, params, task.user_sub)

            task.last_run = now
            task.next_run = task.calculate_next_run(from_date=now)
            db.session.commit()
            logging.info(f"Tâche #{task.id} reprogrammée pour {task.next_run}.")

    return len(due_tasks)


@celery.task(acks_late=True, throws=(Exception,))
def run_cve_analysis(cve_id: str) -> dict:
    """Interroge l'API NVD, décode et traduit les informations d'une CVE."""
    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        logging.info(f"Début de l'analyse API pour la CVE : {cve_id}")
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            time.sleep(1)
            response = requests.get(api_url, timeout=15)
            response.raise_for_status()
            data = response.json()
            if not data.get("vulnerabilities"):
                raise Exception(f"La CVE '{cve_id}' n'a pas été trouvée dans la base de données NVD.")
            cve_data = data["vulnerabilities"][0]["cve"]
            description = next((d['value'] for d in cve_data.get('descriptions', []) if d['lang'] == 'en'), "Description non disponible.")
            cvss_metrics = cve_data.get("metrics", {})
            cvss_v3_data = cvss_metrics.get("cvssMetricV31", cvss_metrics.get("cvssMetricV30", [{}]))[0].get("cvssData", {})

            result = {
                "id": cve_data.get("id"),
                "description": description,
                "score": cvss_v3_data.get("baseScore"),
                "severity": cvss_v3_data.get("baseSeverity"),
            }
            logging.info(f"Analyse API de {cve_id} réussie.")
            return result
        except requests.exceptions.RequestException as e:
            logging.error(f"Erreur de communication avec l'API NVD pour {cve_id}: {e}")
            raise Exception("Impossible de contacter le service d'analyse des vulnérabilités (NVD).")
        except Exception as e:
            logging.error(f"Erreur inattendue lors de l'analyse de {cve_id}: {e}", exc_info=True)
            raise


@celery.task(acks_late=True)
def analyze_report_for_vulns(report_id: int, report_text: str) -> list[int]:
    """
    Analyse le texte d'un rapport, extrait les CVEs et les enregistre en base de données.
    Retourne la liste des IDs des vulnérabilités créées.
    """
    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        logging.info(f"Analyse du rapport #{report_id} pour les vulnérabilités...")
        report = Report.query.get(report_id)
        if not report:
            logging.error(f"Rapport #{report_id} non trouvé pour l'analyse des vulnérabilités.")
            return []

        cve_ids_found = _extract_cves_from_text(report_text)
        created_vuln_ids = []

        if not cve_ids_found:
            logging.info(f"Aucune CVE trouvée dans le rapport #{report_id}.")
            return []

        for cve_id in cve_ids_found:
            existing_vuln = Vulnerability.query.filter_by(
                report_id=report.id,
                cve_id=cve_id,
                user_sub=report.user_sub
            ).first()

            if not existing_vuln:
                new_vuln = Vulnerability(
                    report_id=report.id,
                    user_sub=report.user_sub,
                    cve_id=cve_id,
                    summary="En cours d'enrichissement...",
                    component="Extrait du rapport"
                )
                db.session.add(new_vuln)
                db.session.flush()
                created_vuln_ids.append(new_vuln.id)
                logging.info(f"CVE '{cve_id}' ajoutée comme vulnérabilité #{new_vuln.id} pour le rapport #{report.id}.")
            else:
                logging.info(f"CVE '{cve_id}' existe déjà pour le rapport #{report.id}. Ignorée.")
        db.session.commit()
        logging.info(f"Analyse du rapport #{report.id} terminée. {len(created_vuln_ids)} nouvelles vulnérabilités ajoutées.")
        return created_vuln_ids


@celery.task(acks_late=True)
def enrich_vulnerability_details(vuln_id: int):
    """Tente de récupérer les détails d'une CVE et met à jour la vulnérabilité en base."""
    app = create_app(register_blueprints=False, register_context_processors=False)
    with app.app_context():
        vuln = Vulnerability.query.get(vuln_id)
        if not vuln:
            logging.error(f"Impossible d'enrichir la vulnérabilité #{vuln_id}, non trouvée.")
            return

        try:
            cve_details = run_cve_analysis.run(vuln.cve_id)
            if cve_details:
                vuln.summary = cve_details.get('description', vuln.summary)
                vuln.cvss_score = cve_details.get('score', vuln.cvss_score)
                vuln.severity = cve_details.get('severity', vuln.severity)
                db.session.commit()
                logging.info(f"Vulnérabilité #{vuln_id} ({vuln.cve_id}) enrichie avec succès.")
            else:
                logging.warning(f"L'appel à run_cve_analysis pour {vuln.cve_id} n'a retourné aucun détail.")
        except Exception as e:
            logging.warning(f"Échec de l'enrichissement pour la vulnérabilité #{vuln_id} ({vuln.cve_id}): {e}")


def _extract_cves_from_text(text: str) -> set[str]:
    """Extrait les identifiants CVE (ex: CVE-2021-44228) d'un texte."""
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE))