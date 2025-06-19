# modules/reporting_global.py
import shlex
import logging

# --- On importe les modules qui serviront de briques de base ---
from modules.subdomain_takeover import MODULE as mod_takeover
from modules.code_secrets_scanner import MODULE as mod_secrets
from modules.osint_global import MODULE as mod_osint_pseudo
from modules.vuln_global import MODULE as mod_vuln_global
from modules.metasploit_scan import MODULE as mod_metasploit_scan
from modules.aggressive_audit import MODULE as mod_aggressive_audit


# --- Dictionnaire des modules à exécuter pour le rapport de synthèse ---
MODULE_MAP = {
    "subdomain_takeover": mod_takeover,
    "code_secrets_scanner": mod_secrets,
    "osint_pseudo_search": mod_osint_pseudo,
    "vuln_assessment_complet": mod_vuln_global,
    "metasploit_scan": mod_metasploit_scan,
    "aggressive_audit": mod_aggressive_audit,
}

# Liste des choix sous forme (valeur_interne, label_visible) pour le HTML
REPORT_SECTION_CHOICES_FOR_SCHEMA = [
    ("subdomain_takeover", "Subdomain Takeover Scan"),
    ("code_secrets_scanner", "Code Leak Scanner (Gitleaks)"),
    ("osint_pseudo_search", "OSINT – Recherche de Pseudo (GoSearch)"),
    ("vuln_assessment_complet", "Vuln Assessment – Complet"),
    ("metasploit_scan", "Metasploit - Scan d'Exploits Potentiels"),
    ("aggressive_audit", "Audit Agressif"),
]

# Liste des ID de sections par défaut (pour le traitement interne si aucune sélection n'arrive du formulaire)
REPORT_SECTION_IDS_DEFAULT = [choice[0] for choice in REPORT_SECTION_CHOICES_FOR_SCHEMA]


def _get_report_sections_choices_internal():
    """Fonction interne pour retourner les clés des modules disponibles pour le rapport de synthèse (pour le schéma)."""
    return REPORT_SECTION_CHOICES_FOR_SCHEMA

def build_parallel_cmd(params: dict) -> list[str]:
    """
    Construit la commande shell pour exécuter les modules sélectionnés en parallèle.
    """
    parts_bg: list[str] = []
    parts_sequential_output: list[str] = []

    sections_to_run = params.get("sections", [])

    if not sections_to_run:
        logging.warning("Aucune section sélectionnée via le formulaire pour le rapport de synthèse. Utilisation des sections par défaut.")
        sections_to_run = REPORT_SECTION_IDS_DEFAULT

    # Vérification et exécution des modules
    for sec_id in sections_to_run:
        if sec_id not in MODULE_MAP:
            logging.warning(f"Section '{sec_id}' non trouvée dans MODULE_MAP pour le rapport de synthèse. Ignorée.")
            continue

        sub_mod = MODULE_MAP[sec_id]
        sub_params = {}
        sub_params["target"] = params.get("target", "")

        # Mapper la cible principale aux paramètres spécifiques si nécessaire
        if "github_target" in [f['name'] for fg in sub_mod.get("schema", []) for f in fg.get("fields", [])]:
            sub_params["github_target"] = params.get("target", "")
        if "username" in [f['name'] for fg in sub_mod.get("schema", []) for f in fg.get("fields", [])]:
            sub_params["username"] = params.get("target", "")

        # Toujours forcer le mode "full" pour les sous-scans du rapport de synthèse si le champ existe
        if "mode" in [f['name'] for fg in sub_mod.get("schema", []) for f in fg.get("fields", [])]:
            sub_params["mode"] = "full"

        cmd_list = []
        try:
            # Appel de la fonction cmd du sous-module
            cmd_list = sub_mod["cmd"](sub_params)
            logging.info(f"Commande générée pour la section '{sec_id}': {cmd_list}") # NOUVEAU LOG

        except Exception as e:
            logging.error(f"ERREUR lors de la génération de la commande pour le module '{sec_id}' du rapport de synthèse : {e}", exc_info=True) # NOUVEAU LOG
            logging.error(f"Paramètres passés à '{sec_id}': {sub_params}") # NOUVEAU LOG
            continue # Passer au module suivant si la génération de la commande échoue

        single_scan_command = ""
        if len(cmd_list) >= 3 and cmd_list[0] == "bash" and cmd_list[1] == "-c":
            # Si c'est une commande bash -c, s'assurer que le contenu du script est correctement échappé
            script_content_escaped = cmd_list[2].replace("'", "'\"'\"'")
            single_scan_command = f"bash -c '{script_content_escaped}'"
        else:
            # Pour les autres types de commandes (liste d'arguments), les citer avec shlex.quote
            single_scan_command = " ".join(shlex.quote(str(arg)) for arg in cmd_list)

        if not single_scan_command.strip():
            logging.warning(f"Commande de scan générée vide pour la section '{sec_id}' du rapport de synthèse. Elle sera ignorée.")
            continue

        log_file = f"/tmp/report_{sec_id}.log"
        # Exécuter en arrière-plan, rediriger stdout/stderr vers le fichier de log.
        # Ajouter une pause ou un `sleep` pour éviter des soucis de concurrence si nécessaire,
        # bien que `wait` après devrait gérer ça.
        parts_bg.append(f"({single_scan_command}) > {log_file} 2>&1 &")

        section_display_name_quoted = shlex.quote(sub_mod['name'])
        parts_sequential_output.append(f"printf '###-SECTION-START: %s -###\\n' {section_display_name_quoted}")
        parts_sequential_output.append(f"cat {log_file}")
        parts_sequential_output.append(f"printf '###-SECTION-END: %s -###\\n\\n' {section_display_name_quoted}")

    if not parts_bg:
        logging.error("Aucune commande de scan valide n'a été construite pour le rapport de synthèse.")
        return ["bash", "-c", "echo 'ERREUR: Aucune section valide à inclure dans le rapport de synthèse.' && exit 1"]

    cmd_parallel_str = " ".join(parts_bg)
    cmd_sequential_output_str = "\n".join(parts_sequential_output)

    final_shell_script = f"""
set -e

echo "[+] Démarrage des scans pour le rapport de synthèse. Les logs sont temporairement dans /tmp/report_*.log"

# Exécuter tous les scans en parallèle en arrière-plan
{cmd_parallel_str}

# Attendre que tous les processus en arrière-plan se terminent
wait

echo "[+] Tous les scans parallèles sont terminés. Agrégation des résultats."

# Afficher les résultats séquentiellement pour le rapport final
{cmd_sequential_output_str}

echo "[+] Génération du rapport de synthèse terminée."
"""
    return ["bash", "-c", final_shell_script]


MODULE = {
    "name": "Générateur de Rapport de Synthèse",
    "description": "Génère un rapport PDF modulable combinant plusieurs scans OSINT et de vulnérabilités sur une cible.",
    "category": "Reporting",
    "hidden_from_list": True,
    "schema": [
        {
            "group_name": "Configuration du Rapport",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "domaine.com ou orga_github",
                    "required": True,
                    "description": "Cible principale qui sera utilisée pour tous les scans sélectionnés."
                },
                {
                    "name": "sections",
                    "type": "multiselect",
                    "choices": REPORT_SECTION_CHOICES_FOR_SCHEMA,
                    "default": REPORT_SECTION_IDS_DEFAULT,
                    "description": "Cochez les sections à inclure dans le rapport final."
                },
            ]
        }
    ],
    "cmd": lambda p: build_parallel_cmd(p),
}