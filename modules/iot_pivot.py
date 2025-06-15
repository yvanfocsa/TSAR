# modules/iot_pivot.py
import shlex

# La logique de génération est maintenant dans le backend (tasks.py).
# Le module ne fait que définir les actions et les paramètres.
MODULE = {
    "name": "IoT - Pivot VPN",
    "description": "Gère le tunnel VPN et lance des audits sur le réseau distant pour les appareils IoT.",
    "category": "Scan Réseau", # Catégorie mise à jour
    "schema": [
        # Le schéma est maintenant groupé pour la cohérence
        {
            "group_name": "Actions VPN & Scan",
            "fields": [
                {
                    "name": "action",
                    "type": "select",
                    "choices": [
                        "generate_config",
                        "start_vpn",
                        "stop_vpn",
                        "scan_network",
                        "scan_iot_vulns",
                    ],
                    "default": "generate_config",
                    "required": True,
                },
                {
                    "name": "public_ip",
                    "type": "string",
                    "placeholder": "Votre IP publique (ou nom de domaine)",
                    "required": False,
                },
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "Ex: 192.168.1.0/24 ou 192.168.1.50",
                    "required": False,
                },
            ]
        }
    ],
    "cmd": lambda p: _build_command(p),
}


def _build_command(p: dict) -> list[str]:
    action = p.get("action")
    target = p.get("target", "")

    # La génération est un cas spécial géré par le worker Celery.
    # On renvoie une commande simple pour que le worker sache quoi faire.
    # Le résultat (le "one-liner") sera géré par le frontend.
    if action == "generate_config":
        return ["echo", "Génération de la configuration VPN automatisée..."]
    
    elif action == "start_vpn":
        return ["wg-quick", "up", "/etc/wireguard/wg0.conf"]
    
    elif action == "stop_vpn":
        return ["wg-quick", "down", "/etc/wireguard/wg0.conf"]
    
    elif action == "scan_network":
        if not target:
            return ["echo", "ERREUR: Veuillez fournir une cible pour le scan réseau."]
        return ["nmap", "-sP", "-T4", shlex.quote(target)]
    
    elif action == "scan_iot_vulns":
        if not target:
            return ["echo", "ERREUR: Veuillez fournir une cible pour le scan IoT."]
        return [
            "bash",
            "-c",
            f"""
            echo '[+] Lancement du scan de ports IoT sur {shlex.quote(target)}...'
            nmap -p 1883,8883,5683,5684,61613,61614 {shlex.quote(target)} || true
            
            echo '\\n[+] Lancement de Nuclei avec les templates IoT...'
            nuclei -t iot -u {shlex.quote(target)} || true
            """,
        ]
    else:
        return ["echo", "Action non reconnue."]
