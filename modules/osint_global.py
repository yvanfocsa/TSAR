# modules/osint_global.py
MODULE = {
    "name": "OSINT – Recherche de Pseudo (GoSearch)",
    "description": "Traque un nom d'utilisateur sur plus de 300 sites pour trouver des comptes associés.",
    "category": "OSINT",
    "schema": [
        {
            "group_name": "Paramètres de Recherche",
            "fields": [
                {
                    "name": "username",
                    "type": "string",
                    "placeholder": "Ex: johndoe, ninja_coder",
                    "required": True
                },
                {
                    "name": "mode",
                    "type": "select",
                    "choices": ["quick", "full"],
                    "default": "quick",
                    "description": "Les deux modes effectuent le même scan complet (l'outil ne gère pas de timeout)."
                },
            ]
        }
    ],
    # MODIFIÉ : Ajout du flag --no-false-positives pour des résultats plus fiables.
    "cmd": lambda p: [
        "gosearch",
        "-u",
        p.get("username", ""),
        "--no-false-positives"
    ],
}
