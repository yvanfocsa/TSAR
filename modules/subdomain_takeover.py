# modules/subdomain_takeover.py
import shlex

MODULE = {
    "name": "Subdomain Takeover Scan",
    "description": "Détecte les sous-domaines vulnérables à une prise de contrôle (takeover).",
    "category": "Recon",
    "schema": [
        {
            "group_name": "Paramètres du Scan",
            "fields": [
                {"name": "target", "type": "string", "placeholder": "domaine.com", "required": True},
            ]
        }
    ],
    "cmd": lambda p: [
        "bash", "-c",
        (
            f"echo '[+] Recherche des sous-domaines pour {shlex.quote(p['target'])}...'; "
            f"subfinder -d {shlex.quote(p['target'])} -silent | "
            f"tee /tmp/subdomains_for_takeover.txt | "
            f"echo \"[+] $(wc -l < /tmp/subdomains_for_takeover.txt) sous-domaines trouvés. Lancement de Nuclei...\"; "
            f"cat /tmp/subdomains_for_takeover.txt | nuclei -t takeovers/ -c 50"
        )
    ],
}
