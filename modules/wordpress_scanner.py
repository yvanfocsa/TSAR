# modules/wordpress_scanner.py
MODULE = {
    "name": "WordPress - WPProbe",
    "description": "Scanner WordPress rapide et discret via l'API REST.",
    "category": "Web",
    "schema": [
        {"name": "url", "type": "string", "placeholder": "https://site-wordpress.com", "required": True},
    ],
    "cmd": lambda p: ["wpprobe", "-u", p["url"]],
}