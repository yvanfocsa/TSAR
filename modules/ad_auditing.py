# modules/ad_auditing.py
MODULE = {
    "name": "Active Directory - ADMiner",
    "description": "Audit complet et continu d'Active Directory avec ADMiner.",
    "category": "Active Directory",
    "schema": [
        {"name": "ldap_server", "type": "string", "placeholder": "IP du contrôleur de domaine", "required": True},
        {"name": "username", "type": "string", "placeholder": "utilisateur@domaine.local", "required": True},
        {"name": "password", "type": "string", "placeholder": "Mot de passe", "required": True},
    ],
    "cmd": lambda p: [
        "adminer",
        "--server", p["ldap_server"],
        "--username", p["username"],
        "--password", p["password"],
        "all", # Lance tous les checks
        "--html", # Génère un rapport HTML
    ],
}