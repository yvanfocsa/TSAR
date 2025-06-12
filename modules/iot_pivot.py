# modules/iot_pivot.py
import shlex

MODULE = {
    "name": "IoT - Pivot VPN",
    "description": "Gère le tunnel VPN et lance des audits sur le réseau distant pour les appareils IoT.",
    "category": "IoT & Pivot",
    "schema": [
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
    ],
    "cmd": lambda p: _build_command(p),
}


def _build_command(p: dict) -> list[str]:
    action = p.get("action")
    target = p.get("target", "")

    if action == "generate_config":
        return [
            "bash",
            "-c",
            f"""
            set -e
            echo '[+] Génération des clés et configurations VPN...'
            cd /etc/wireguard
            wg genkey | tee server_private.key | wg pubkey > server_public.key
            wg genkey | tee client_private.key | wg pubkey > client_public.key
            SERVER_PRIVATE_KEY=$(cat server_private.key)
            CLIENT_PRIVATE_KEY=$(cat client_private.key)
            CLIENT_PUBLIC_KEY=$(cat client_public.key)
            
            echo "[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32" > wg0.conf

            echo "[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = {shlex.quote(p.get("public_ip", "VOTRE_IP_PUBLIQUE"))}:51820
AllowedIPs = 0.0.0.0/0, ::/0 # Permet de router tout le trafic
PersistentKeepalive = 25" > client.conf

            chmod 600 *_private.key wg0.conf client.conf
            
            echo '[+] Terminé !'
            echo '======================================================================'
            echo '  ACTION REQUISE : '
            echo '  1. Récupérez le fichier "client.conf" dans le dossier "vpn_configs".'
            echo "  2. Si besoin, modifiez-le pour ajouter votre IP publique."
            echo "  3. Transférez-le sur votre implant dans /etc/wireguard/wg0.conf"
            echo '======================================================================'
            """,
        ]
    elif action == "start_vpn":
        return ["wg-quick", "up", "/etc/wireguard/wg0.conf"]
    elif action == "stop_vpn":
        return ["wg-quick", "down", "/etc/wireguard/wg0.conf"]
    elif action == "scan_network":
        if not target:
            return ["echo", "ERREUR: Veuillez fournir une cible pour le scan réseau."]
        return [
            "nmap",
            "-sP",  # Ping scan pour découvrir les hôtes actifs
            "-T4",
            shlex.quote(target),
        ]
    elif action == "scan_iot_vulns":
        if not target:
            return ["echo", "ERREUR: Veuillez fournir une cible pour le scan IoT."]
        # Combine Nmap pour les ports IoT et Nuclei avec des templates spécifiques
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
