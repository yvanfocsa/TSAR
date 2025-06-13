# modules/omega_scan.py
import shlex

# --- On importe TOUS les modules qui serviront de briques de base ---
from modules.intelligence_gathering import MODULE as mod_intel
from modules.code_secrets_scanner import MODULE as mod_secrets
from modules.subdomain_takeover import MODULE as mod_takeover
from modules.vulnerability_analysis import MODULE as mod_vuln
from modules.exploitation import MODULE as mod_exploit

# --- Dictionnaire des modules à exécuter, dans un ordre logique ---
# Les clés numérotées aident à organiser la sortie du rapport.
OMEGA_MODULES = {
    "1_recon_osint": mod_intel,
    "2_leak_scan": mod_secrets,
    "3_takeover_scan": mod_takeover,
    "4_vuln_analysis": mod_vuln,
    "5_exploitation": mod_exploit,
}

# --- Construction dynamique du schéma pour le formulaire ---
def _build_omega_schema():
    """
    Combine les paramètres de tous les sous-modules pour le formulaire.
    """
    return [
        {
            "group_name": "Paramètres de Cible Principale",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "exemple.com ou 1.2.3.4",
                    "required": True,
                    "description": "Cible principale pour la plupart des scans (Nmap, Nuclei, etc.)."
                },
                {
                    "name": "service",
                    "type": "string",
                    "placeholder": "ssh, ftp, http (pour Hydra)",
                    "required": False,
                    "description": "Service à cibler pour le bruteforce avec Hydra."
                },
            ],
        },
        {
            "group_name": "Paramètres OSINT (Optionnel)",
            "fields": [
                {
                    "name": "github_target",
                    "type": "string",
                    "placeholder": "Nom d'orga/user GitHub (ex: tesla)",
                    "required": False,
                    "description": "Si fourni, lance un scan de secrets sur les dépôts publics associés."
                },
            ]
        }
    ]

# --- Définition du module Omega ---
MODULE = {
    "name": "Omega Scan",
    "description": "Lancement d'un audit complet et automatisé sur une cible, combinant toutes les phases du PTES.",
    "category": "Scans Complets",
    "schema": _build_omega_schema(),
    "cmd": lambda p: _build_omega_cmd(p),
}

# --- Construction de la commande shell complexe ---
def _build_omega_cmd(p: dict) -> list[str]:
    """
    Construit la commande shell pour exécuter tous les modules en parallèle.
    """
    parts_bg: list[str] = []
    parts_cat: list[str] = []

    for name, sub_mod in OMEGA_MODULES.items():
        # Préparation des paramètres pour chaque sous-module
        sub_params = p.copy()
        sub_params["mode"] = "full" # Toujours en mode complet pour Omega

        # Gère les cas où un paramètre est manquant pour un sous-module
        if name == "2_leak_scan" and not p.get("github_target"):
            print(f"Skipping {name}: github_target not provided.")
            continue
        
        # Gère les alias de paramètres (ex: 'target' pour gitleaks)
        if name == "2_leak_scan":
            sub_params["github_target"] = p.get("github_target")

        # Construction de la commande pour le sous-module
        cmd_list = sub_mod["cmd"](sub_params)
        single_cmd = " ".join(shlex.quote(str(part)) for part in cmd_list)

        # Redirige la sortie vers un log temporaire et lance en arrière-plan
        log_file = f"/tmp/omega_{name}.log"
        parts_bg.append(f"({single_cmd}) > {log_file} 2>&1 &")

        # Prépare la commande pour afficher le contenu du log plus tard
        parts_cat.append(
            f"echo '\\n\\n===== Début section {sub_mod['name']} =====' && cat {log_file}"
        )

    if not parts_bg:
        return ["bash", "-c", "echo 'Aucun sous-module n'a pu être configuré pour Omega.'"]

    # Commande finale: lance tout en parallèle, attend la fin, puis affiche les logs
    cmd_parallel = " && ".join(parts_bg)
    cmd_wait_and_cat = "wait && " + " && ".join(parts_cat)
    final_shell_cmd = f"{cmd_parallel} && {cmd_wait_and_cat}"

    return ["bash", "-c", final_shell_cmd]
