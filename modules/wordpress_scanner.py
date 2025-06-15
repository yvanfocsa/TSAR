# modules/wordpress_scanner.py
MODULE = {
    "name": "WPProbe",
    "description": "Scanner WordPress rapide et discret via l'API REST.",
    "category": "Wordpress",  # Catégorie mise à jour
    "schema": [
        {
            "group_name": "Paramètres du Scan",
            "fields": [
                {
                    "name": "url",
                    "type": "string",
                    "placeholder": "https://site-wordpress.com",
                    "required": True
                },
            ]
        }
    ],
    "cmd": lambda p: ["wpprobe", "-u", p["url"]],
}
