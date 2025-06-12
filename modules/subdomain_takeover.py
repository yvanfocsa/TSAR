# modules/subdomain_takeover.py
import shlex

MODULE = {
    "name": "Subdomain Takeover Scan",
    "description": "Détecte les sous-domaines vulnérables à une prise de contrôle (takeover) en vérifiant les enregistrements CNAME pointant vers des services tiers expirés.",
    "category": "Recon", # S'intègre bien dans la phase de reconnaissance
    "schema": [
        {
            "name": "target",
            "type": "string",
            "placeholder": "domaine.com",
            "required": True,
        },
    ],
    "cmd": lambda p: [
        "bash",
        "-c",
        # La commande enchaîne subfinder pour trouver les sous-domaines,
        # puis les envoie à nuclei qui utilise uniquement ses templates
        # spécialisés dans la détection de takeovers.
        (
            f"echo '[+] Recherche des sous-domaines pour {shlex.quote(p['target'])}...'; "
            f"subfinder -d {shlex.quote(p['target'])} -silent | "
            f"tee /tmp/subdomains_for_takeover.txt | "
            f"echo \"[+] $(wc -l < /tmp/subdomains_for_takeover.txt) sous-domaines trouvés. Lancement de Nuclei...\"; "
            f"cat /tmp/subdomains_for_takeover.txt | nuclei -t takeovers/ -c 50"
        )
    ],
}
