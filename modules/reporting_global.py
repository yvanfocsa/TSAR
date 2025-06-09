# modules/reporting_global.py
import shlex

# --- Les imports devraient maintenant fonctionner ---
from modules.intelligence_gathering import MODULE as _mod_intel
from modules.vulnerability_analysis import MODULE as _mod_vuln
from modules.exploitation           import MODULE as _mod_exploit

# ─────────── Mapping section → module ───────────
MODULE_MAP = {
    "intelligence": _mod_intel,
    "vulnerability": _mod_vuln,
    "exploitation": _mod_exploit,
}

MODULE = {
    "name": "7. Reporting",
    "description": "Génère le rapport PDF modulable et chiffré basé sur les phases du PTES.",
    "category": "PTES - Phase 7",
    "binary": "rapport",
    "hidden": False,
    "schema": [
        {
            "name": "target",
            "type": "string",
            "placeholder": "exemple.com ou 1.2.3.4",
            "required": True,
        },
        {
            "name": "sections",
            "type": "multiselect",
            "choices": list(MODULE_MAP.keys()),
        },
    ],
    "cmd": lambda p: _build_report_cmd(p),
}

def _build_report_cmd(p: dict) -> list[str]:
    """
    Construit la commande shell pour générer le rapport en parallèle.
    """
    parts_bg:  list[str] = []
    parts_cat: list[str] = []

    for sec in p.get("sections", []):
        if sec not in MODULE_MAP:
            continue

        sub_params = {
            "target": p.get("target", ""),
            "mode":   "full", 
        }
        
        if "service" in [s["name"] for s in MODULE_MAP[sec].get("schema", [])]:
            sub_params["service"] = p.get("service", "")

        cmd_list   = MODULE_MAP[sec]["cmd"](sub_params)
        single_cmd = " ".join(shlex.quote(str(part)) for part in cmd_list)

        parts_bg.append(f"({single_cmd}) > /tmp/{sec}.log 2>&1 &")
        parts_cat.append(
            f"echo '===== Début section {sec} =====' && cat /tmp/{sec}.log"
        )

    if not parts_bg:
        return ["bash", "-c", "echo 'Aucune section sélectionnée'"]

    cmd_parallel      = " && ".join(parts_bg)
    cmd_wait_and_cat  = "wait && " + " && ".join(parts_cat)
    final_shell_cmd   = f"{cmd_parallel} && {cmd_wait_and_cat}"

    return ["bash", "-c", final_shell_cmd]
