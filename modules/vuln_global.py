# modules/vuln_global.py
import shlex

MODULE = {
    "name": "Vuln Assessment – Complet",
    "description": "Combine Nuclei, Nikto, OpenVAS et WPScan pour un audit de vulnérabilités web exhaustif.",
    "category": "Scans Complets",
    "hidden_from_list": False,
    # MODIFIÉ : Utilisation de la nouvelle structure de schéma groupé
    "schema": [
        {
            "group_name": "Paramètres du Scan",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "exemple.com ou 1.2.3.4",
                    "required": True,
                    "description": "La cible unique à scanner. Les domaines ou adresses IP sont acceptés."
                },
                {
                    "name": "mode",
                    "type": "select",
                    "choices": ["quick", "full"],
                    "default": "quick",
                    "description": "Quick: Lance Nuclei et Nikto. Full: Ajoute OpenVAS et WPScan (beaucoup plus long)."
                },
            ]
        }
    ],
    "cmd": lambda p: {
        "quick": [
            "bash", "-c",
            " && ".join([
                f"nuclei -u {shlex.quote(p['target'])} -no-color -stats -no-interactsh || true",
                f"nikto -h {shlex.quote(p['target'])} || true",
            ])
        ],
        "full": [
            "bash", "-c",
            " && ".join([
                f"nuclei -u {shlex.quote(p['target'])} -no-color -stats -no-interactsh || true",
                f"nikto -h {shlex.quote(p['target'])} || true",
                f"openvas-cli -h {shlex.quote(p['target'])} || true",
                # Ajout de flags pour un scan wpscan plus sûr et plus efficace
                f"wpscan --url {shlex.quote(p['target'])} --enumerate u --random-user-agent --disable-tls-checks || true",
            ])
        ],
    }[p.get("mode", "quick")],
}
