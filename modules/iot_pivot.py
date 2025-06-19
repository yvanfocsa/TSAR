# modules/iot_pivot.py
import shlex

MODULE = {
    "name": "Pivot & Audit Réseau Interne",
    "description": "Gère un pivot VPN WireGuard et lance des audits de sécurité complets sur le réseau interne cible.",
    "category": "Scan Réseau",
    "schema": [
        {
            "group_name": "Actions sur le Pivot",
            "fields": [
                {
                    "name": "action",
                    "type": "select",
                    "choices": [
                        "generate_config",
                        "start_vpn",
                        "stop_vpn",
                        "audit_reseau_complet",
                        "audit_iot_specifique",
                    ],
                    "default": "generate_config",
                    "required": True,
                },
                {
                    "name": "target_os",
                    "type": "select",
                    "choices": ["Linux", "Windows"],
                    "default": "Linux",
                    "description": "Système d'exploitation de la machine 'implant' pour le pivot.",
                    "required": False,
                },
                {
                    "name": "public_ip",
                    "type": "string",
                    "placeholder": "Votre IP publique (ou nom de domaine)",
                    "required": False,
                },
                {
                    "name": "client_lan_cidr", # <--- NOUVEAU CHAMP ICI !
                    "type": "string",
                    "placeholder": "Ex: 10.0.2.0/24 ou 192.168.1.0/24",
                    "required": False,
                    "description": "Le CIDR du réseau interne auquel la machine implant a accès. Le serveur TSAR routé via ce réseau."
                },
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "Ex: 192.168.1.0/24",
                    "required": False,
                    "description": "La plage d'adresses du réseau interne à auditer."
                },
            ]
        }
    ],
    "cmd": lambda p: _build_command(p),
}


def _build_command(p: dict) -> list[str]:
    action = p.get("action")
    target = p.get("target", "")

    if action == "generate_config":
        target_os = p.get("target_os", "Linux")
        # Le résultat de cette action est géré par app.tasks.run_job pour générer les scripts
        # On ne passe pas target_lan_cidr à l'echo, car il sera utilisé en interne par tasks.py
        return ["echo", f"Génération de la configuration VPN pour {target_os}... (Pensez à saisir le CIDR du réseau interne de la machine implant.)"]

    elif action == "start_vpn":
        return ["bash", "-c", "wg-quick down wg0 2>/dev/null || true && wg-quick up wg0"]

    elif action == "stop_vpn":
        return ["wg-quick", "down", "/etc/wireguard/wg0.conf"]

    elif action == "audit_reseau_complet":
        if not target:
            return ["echo", "ERREUR: Veuillez fournir une plage d'adresses cible (ex: 192.168.1.0/24)."]

        target_quoted = shlex.quote(target)
        command = f"""
        set -e

        echo "\\n###-ACTION-START: Préparation du tunnel WireGuard dans le conteneur toolbox -###"
        echo "[+] Tentative d'arrêt du tunnel wg0 précédent pour nettoyage..."
        wg-quick down wg0 2>/dev/null || true
        echo "[+] Démarrage du serveur WireGuard (wg0) dans le conteneur toolbox..."
        wg-quick up wg0
        echo "[+] Tunnel WireGuard (wg0) est maintenant actif dans le conteneur toolbox."
        echo "###-ACTION-END: Préparation du tunnel WireGuard dans le conteneur toolbox -###\\n"

        echo "###-SECTION-START: 1. Découverte des Hôtes Actifs -###"
        echo "[+] Lancement de la découverte d'hôtes sur {target_quoted} via wg0..."
        arp-scan --interface=wg0 --quiet --ignoredups {target_quoted} | grep -E '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' | awk '{{print $1}}' > /tmp/hosts.txt || true
        nmap -sn -e wg0 {target_quoted} | grep "Nmap scan report for" | awk '{{print $5}}' >> /tmp/hosts.txt || true

        sort -u /tmp/hosts.txt -o /tmp/hosts.txt

        HOST_COUNT=$(wc -l < /tmp/hosts.txt | xargs)
        if [ "$HOST_COUNT" -eq 0 ]; then
            echo "[!] Aucun hôte actif trouvé sur le réseau. Fin de l'audit."
            echo "[+] Arrêt du tunnel WireGuard (wg0) dans le conteneur toolbox..."
            wg-quick down wg0
            echo "[+] Tunnel WireGuard (wg0) est maintenant inactif."
            exit 0
        fi
        echo "[+] $HOST_COUNT hôte(s) actif(s) trouvé(s) :"
        cat /tmp/hosts.txt
        echo "###-SECTION-END: 1. Découverte des Hôtes Actifs -###"

        echo "\\n###-SECTION-START: 2. Scan de Ports et Services -###"
        echo "[+] Lancement du scan de ports et services sur les hôtes découverts (via wg0)..."
        nmap -iL /tmp/hosts.txt -sV -sC -T4 --open -e wg0
        echo "###-SECTION-END: 2. Scan de Ports et Services -###"

        echo "\\n###-SECTION-START: 3. Énumération des Services Windows (SMB) -###"
        echo "[+] Recherche d'hôtes avec le port 445 (SMB) ouvert..."
        echo "[i] Pour cette démonstration, nous allons tenter d'énumérer SMB sur tous les hôtes découverts, si le port 445 est potentiellement ouvert."
        SMB_HOSTS=""
        for host in $(cat /tmp/hosts.txt); do
            nmap -p 445 "$host" | grep -q "445/tcp open" && SMB_HOSTS="$SMB_HOSTS $host" || true
        done

        if [ -n "$SMB_HOSTS" ]; then
            echo "[+] Hôtes SMB détectés : $SMB_HOSTS. Lancement de enum4linux-ng..."
            for host in $SMB_HOSTS; do
                echo "\\n[+] === Énumération de $host ===\\n"
                enum4linux-ng -A "$host" || echo "Erreur lors de l'énumération de $host"
            done
        else
            echo "[-] Aucun service SMB (port 445) détecté sur les hôtes actifs."
        fi
        echo "###-SECTION-END: 3. Énumération des Services Windows (SMB) -###"

        echo "\\n[+] Audit réseau complet terminé."

        echo "\\n###-ACTION-START: Nettoyage du tunnel WireGuard dans le conteneur toolbox -###"
        echo "[+] Arrêt du tunnel WireGuard (wg0) dans le conteneur toolbox..."
        wg-quick down wg0
        echo "[+] Tunnel WireGuard (wg0) est maintenant inactif."
        echo "###-ACTION-END: Nettoyage du tunnel WireGuard dans le conteneur toolbox -###"
        """
        return ["bash", "-c", command]

    elif action == "audit_iot_specifique":
        if not target:
            return ["echo", "ERREUR: Veuillez fournir une cible pour l'audit IoT."]

        target_quoted = shlex.quote(target)
        command = f"""
        set -e

        echo "\\n###-ACTION-START: Préparation du tunnel WireGuard dans le conteneur toolbox -###"
        echo "[+] Tentative d'arrêt du tunnel wg0 précédent pour nettoyage..."
        wg-quick down wg0 2>/dev/null || true
        echo "[+] Démarrage du serveur WireGuard (wg0) dans le conteneur toolbox..."
        wg-quick up wg0
        echo "[+] Tunnel WireGuard (wg0) est maintenant actif dans le conteneur toolbox."
        echo "###-ACTION-END: Préparation du tunnel WireGuard dans le conteneur toolbox -###\\n"

        echo "###-SECTION-START: 1. Scan des Ports Communs IoT -###"
        echo "[+] Lancement du scan des ports IoT sur {target_quoted} via wg0..."
        nmap -p 1883,8883,5683,5684,61613,61614 -e wg0 {target_quoted} --open
        echo "###-SECTION-END: 1. Scan des Ports Communs IoT -###"

        echo "\\n###-SECTION-START: 2. Scan de Vulnérabilités IoT (Nuclei) -###"
        echo "[+] Lancement de Nuclei avec les templates spécifiques à l'IoT (via wg0)..."
        nuclei -t iot -u {target_quoted} -no-color -stats -no-interactsh
        echo "###-SECTION-END: 2. Scan de Vulnérabilités IoT (Nuclei) -###"

        echo "\\n###-ACTION-START: Nettoyage du tunnel WireGuard dans le conteneur toolbox -###"
        echo "[+] Arrêt du tunnel WireGuard (wg0) dans le conteneur toolbox..."
        wg-quick down wg0
        echo "[+] Tunnel WireGuard (wg0) est maintenant inactif."
        echo "###-ACTION-END: Nettoyage du tunnel WireGuard dans le conteneur toolbox -###"
        """
        return ["bash", "-c", command]

    else:
        return ["echo", "Action non reconnue."]