# modules/osint_global.py
MODULE = {
    "name": "OSINT – Recherche de Pseudo (GoSearch)",
    "description": "Traque un nom d'utilisateur sur plus de 300 sites pour trouver des comptes associés.",
    "category": "Recon",
    "schema": [
        {
            "group_name": "Paramètres de Recherche",
            "fields": [
                {"name": "username", "type": "string", "placeholder": "Ex: johndoe, ninja_coder", "required": True},
                {"name": "mode", "type": "select", "choices": ["quick", "full"], "default": "quick"},
            ]
        }
    ],
    "cmd": lambda p: {
        "quick": ["gosearch", "-t", "10", p.get("username", "")],
        "full": ["gosearch", p.get("username", "")],
    }[p.get("mode", "quick")],
}
