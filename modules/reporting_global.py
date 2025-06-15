# modules/reporting_global.py
import shlex

# --- On importe les modules qui serviront de briques de base ---
from modules.subdomain_takeover import MODULE as mod_takeover
from modules.code_secrets_scanner import MODULE as mod_secrets

# --- Dictionnaire des modules à exécuter ---
MODULE_MAP = {
    "subdomain_takeover": mod_takeover,
    "code_secrets": mod_secrets,
}

def build_parallel_cmd(params: dict, module_map: dict) -> list[str]:
    """
    Construit la commande shell pour exécuter les modules sélectionnés en parallèle.
    """
    parts_bg: list[str] = []
    parts_cat: list[str] = []
    
    sections_to_run = params.get("sections", [])

    for sec in sections_to_run:
        if sec not in module_map:
            continue

        sub_mod = module_map[sec]
        sub_params = {
            "target": params.get("target", ""),
            "github_target": params.get("target", ""), # On utilise la même cible pour les deux
        }

        cmd_list = sub_mod["cmd"](sub_params)
        single_cmd = " ".join(shlex.quote(str(part)) for part in cmd_list)

        parts_bg.append(f"({single_cmd}) > /tmp/{sec}.log 2>&1 &")
        parts_cat.append(
            f"echo '===== Début section {sub_mod['name']} =====' && cat /tmp/{sec}.log"
        )

    if not parts_bg:
        return ["bash", "-c", "echo 'Aucune section sélectionnée pour le rapport.'"]

    cmd_parallel = " && ".join(parts_bg)
    cmd_wait_and_cat = "wait && " + " && ".join(parts_cat)
    final_shell_cmd = f"{cmd_parallel} && {cmd_wait_and_cat}"

    return ["bash", "-c", final_shell_cmd]


MODULE = {
    "name": "7. Reporting",
    "description": "Génère un rapport PDF modulable combinant plusieurs scans OSINT.",
    "category": "Reporting", # Catégorie non affichée mais logique
    "hidden": False,
    "hidden_from_list": True,  # Correct : ne pas afficher dans la liste des modules
    "schema": [
        {
            "name": "target",
            "type": "string",
            "placeholder": "domaine.com ou orga_github",
            "required": True,
        },
        {
            "name": "sections",
            "type": "multiselect",
            "choices": list(MODULE_MAP.keys()),
            "default": list(MODULE_MAP.keys()),
        },
    ],
    "cmd": lambda p: build_parallel_cmd(p, MODULE_MAP),
}
