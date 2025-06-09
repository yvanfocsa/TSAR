# modules/omega_scan.py
import shlex

# --- On importe les modules qui serviront de briques de base ---
from modules.intelligence_gathering import MODULE as mod_intel
from modules.vulnerability_analysis import MODULE as mod_vuln
from modules.exploitation import MODULE as mod_exploit

# --- Dictionnaire des modules à exécuter ---
# Clé: nom de la section, Valeur: dictionnaire du module
OMEGA_MODULES = {
    "intelligence": mod_intel,
    "vulnerability": mod_vuln,
    "exploitation": mod_exploit,
}

# --- Construction dynamique du schéma pour le formulaire ---
def _build_omega_schema():
    schema = [
        {
            "group_name": "Paramètres Globaux",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "exemple.com ou 1.2.3.4",
                    "required": True,
                },
                {
                    "name": "service",
                    "type": "string",
                    "placeholder": "ssh, ftp, http (pour hydra)",
                    "required": False,
                },
            ],
        }
    ]
    # On ne demande pas le mode (quick/full), Omega exécute toujours en 'full'
    return schema


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
        sub_params = {
            "target": p.get("target", ""),
            "mode": "full",  # Toujours en mode complet pour Omega
        }
        # Ajoute le paramètre 'service' si le sous-module en a besoin
        if "service" in [
            field["name"] for field in sub_mod.get("schema", [])
        ]:
            sub_params["service"] = p.get("service", "")

        # Construction de la commande pour le sous-module
        cmd_list = sub_mod["cmd"](sub_params)
        single_cmd = " ".join(shlex.quote(str(part)) for part in cmd_list)

        # Redirige la sortie vers un log temporaire et lance en arrière-plan
        parts_bg.append(f"({single_cmd}) > /tmp/omega_{name}.log 2>&1 &")

        # Prépare la commande pour afficher le contenu du log plus tard
        parts_cat.append(
            f"echo '\\n\\n===== Début section {name.capitalize()} =====' && cat /tmp/omega_{name}.log"
        )

    if not parts_bg:
        return ["bash", "-c", "echo 'Aucun sous-module configuré pour Omega.'"]

    # Commande finale: lance tout en parallèle, attend la fin, puis affiche les logs
    cmd_parallel = " && ".join(parts_bg)
    cmd_wait_and_cat = "wait && " + " && ".join(parts_cat)
    final_shell_cmd = f"{cmd_parallel} && {cmd_wait_and_cat}"

    return ["bash", "-c", final_shell_cmd]
