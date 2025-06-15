# modules/omega_scan.py
import shlex

# --- On importe les modules OSINT qui serviront de briques de base ---
from modules.osint_global import MODULE as mod_osint_pseudo
from modules.code_secrets_scanner import MODULE as mod_gitleaks
from modules.subdomain_takeover import MODULE as mod_takeover

# --- Dictionnaire des modules à exécuter, dans un ordre logique ---
OMEGA_MODULES = {
    "1_pseudo_search": mod_osint_pseudo,
    "2_leak_scan": mod_gitleaks,
    "3_takeover_scan": mod_takeover,
}

# --- Construction dynamique du schéma pour le formulaire ---
def _build_omega_schema():
    """
    Combine les paramètres de tous les sous-modules pour le formulaire.
    """
    return [
        {
            "group_name": "Paramètres de Cible",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "domaine.com (pour Subdomain Takeover)",
                    "required": True,
                    "description": "Cible principale pour le scan de takeover de sous-domaines."
                },
                {
                    "name": "username",
                    "type": "string",
                    "placeholder": "pseudonyme (pour la recherche de comptes)",
                    "required": True,
                    "description": "Le nom d'utilisateur à rechercher sur les réseaux sociaux."
                },
                {
                    "name": "github_target",
                    "type": "string",
                    "placeholder": "orga/user GitHub (pour Gitleaks)",
                    "required": True,
                    "description": "Le nom de l'organisation ou de l'utilisateur sur GitHub pour le scan de secrets."
                },
            ],
        }
    ]

# --- Définition du module Omega ---
MODULE = {
    "name": "Omega Scan (OSINT)",
    "description": "Lance un audit OSINT complet et automatisé, combinant la recherche de pseudos, de secrets sur GitHub et de takeovers de sous-domaines.",
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
