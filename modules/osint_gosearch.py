# modules/osint_gosearch.py
MODULE = {
    "name": "OSINT - GoSearch",
    "description": "Traque un nom d'utilisateur sur plus de 300 sites.",
    "category": "OSINT",
    "schema": [
        {"name": "username", "type": "string", "placeholder": "pseudo à rechercher", "required": True},
    ],
    "cmd": lambda p: ["gosearch", p["username"]],
}