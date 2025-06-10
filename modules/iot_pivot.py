# modules/iot_pivot.py
import shlex

MODULE = {
    "name": "IoT - Pivot VPN",
    "description": "Gère le tunnel VPN WireGuard pour pivoter dans un réseau distant et auditer des appareils IoT.",
    "category": "IoT & Pivot",
    "schema": [
        {
            "name": "action",
            "type": "select",
            "choices": ["generate_config", "start_vpn", "stop_vpn"],
            "default": "generate_config",
            "required": True,
        },
        {
            "name": "public_ip",
            "type": "string",
            "placeholder": "Votre IP publique (ou nom de domaine)",
            "required": False,
        },
    ],
    "cmd": lambda p: {
        "generate_config": [
            "bash",
            "-c",
            f"""
            set -e
            echo '[+] Génération des clés et configurations VPN...'
            cd /etc/wireguard
            wg genkey | tee server_private.key | wg pubkey > server_public.key
            wg genkey | tee client_private.key | wg pubkey > client_public.key
            SERVER_PRIVATE_KEY=$(cat server_private.key)
            SERVER_PUBLIC_KEY=$(cat server_public.key)
            CLIENT_PRIVATE_KEY=$(cat client_private.key)
            CLIENT_PUBLIC_KEY=$(cat client_public.key)
            
            # Création du fichier de configuration du serveur (wg0.conf)
            echo "[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32" > wg0.conf

            # Création du fichier de configuration du client (pour l'implant)
            echo "[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = {shlex.quote(p.get("public_ip", "VOTRE_IP_PUBLIQUE"))}:51820
AllowedIPs = 10.0.0.1/32
PersistentKeepalive = 25" > client.conf

            chmod 600 *_private.key wg0.conf client.conf
            
            echo '[+] Terminé !'
            echo '======================================================================'
            echo '  ACTION REQUISE : '
            echo '  1. Récupérez le fichier "client.conf" dans le dossier "vpn_configs" de votre projet.'
            echo "  2. Si vous n'avez pas fourni votre IP publique, modifiez le fichier et remplacez 'VOTRE_IP_PUBLIQUE'."
            echo "  3. Transférez ce fichier sur votre implant (Raspberry Pi) dans /etc/wireguard/wg0.conf"
            echo '======================================================================'
            """,
        ],
        "start_vpn": [
            "wg-quick",
            "up",
            "/etc/wireguard/wg0.conf",
        ],
        "stop_vpn": [
            "wg-quick",
            "down",
            "/etc/wireguard/wg0.conf",
        ],
    }[p["action"]],
}
