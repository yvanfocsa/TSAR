# modules/osint_global.py
"""
OSINT – Recherche de comptes par pseudonyme avec GoSearch.

Cet outil scanne plus de 300 sites (réseaux sociaux, forums, etc.)
pour trouver des comptes associés à un nom d'utilisateur.

Modes :
  • quick : Timeout court pour des résultats rapides.
  • full  : Scan complet avec le timeout par défaut.
"""
import shlex

MODULE = {
    "name": "OSINT – Recherche de Pseudo (GoSearch)",
    "description": "Traque un nom d'utilisateur sur plus de 300 sites pour trouver des comptes associés.",
    "category": "Recon",
    "hidden": False,
    "schema": [
        {
            "name": "username",
            "type": "string",
            "placeholder": "Ex: johndoe, ninja_coder",
            "required": True,
        },
        {
            "name": "mode",
            "type": "select",
            "choices": ["quick", "full"],
            "default": "quick",
        },
    ],
    "cmd": lambda p: {
        "quick": [
            "gosearch",
            "-t", "10",  # Timeout de 10 secondes par site
            p.get("username", ""),
        ],
        "full": [
            "gosearch",
            p.get("username", ""),
        ],
    }[p.get("mode", "quick")],
}
