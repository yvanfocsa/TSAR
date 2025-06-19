# modules/aggressive_audit.py
import shlex

MODULE = {
    "name": "Audit Agressif",
    "description": "Combine Nmap pour la découverte, Nuclei pour la détection de CVEs, et Metasploit pour les failles de configuration. Très complet mais peut être long.",
    "category": "Scans Complets",
    "schema": [
        {
            "group_name": "Paramètres de l'Audit",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "Ex: 192.168.1.7",
                    "required": True,
                    "description": "L'adresse IP unique de la cible. Les plages ne sont pas recommandées pour ce module.",
                },
            ],
        }
    ],
    "cmd": lambda p: _build_command(p),
    # Ce module doit être caché de la liste principale car il est intégré dans les "Scans Complets"
    "hidden_from_list": False,
}


def _build_command(p: dict) -> list[str]:
    target_quoted = shlex.quote(p["target"])

    command = f"""
    set -e
    
    echo "###-SECTION-START: 1. Découverte des Services (Nmap) -###"
    echo "[+] Lancement de Nmap pour identifier les ports et services sur {target_quoted}..."
    # -sV: Détection de version, -oG: Sortie "grepable" pour parsing
    nmap -sV -T4 -oG /tmp/nmap_grepable.log {target_quoted}
    
    echo "[+] Résultats Nmap :"
    cat /tmp/nmap_grepable.log | grep "Ports:"
    echo "###-SECTION-END: 1. Découverte des Services (Nmap) -###"
    
    
    echo "\\n###-SECTION-START: 2. Scan de Vulnérabilités (Nuclei) -###"
    echo "[+] Lancement de Nuclei pour une détection de CVEs à grande échelle..."
    # On utilise -no-interactsh pour les scans automatisés
    nuclei -u {target_quoted} -no-color -stats -no-interactsh || true
    echo "###-SECTION-END: 2. Scan de Vulnérabilités (Nuclei) -###"
    
    
    echo "\\n###-SECTION-START: 3. Scan de Failles de Configuration (Metasploit) -###"
    echo "[+] Démarrage du service PostgreSQL pour Metasploit..."
    service postgresql start || echo "Service PostgreSQL déjà démarré."
    
    # Liste des modules Metasploit à exécuter
    MSF_MODULES=(
        "auxiliary/scanner/ftp/anonymous"
        "auxiliary/scanner/vnc/vnc_login"
        "auxiliary/scanner/telnet/telnet_login"
        "auxiliary/scanner/rservices/rsh_login"
        "auxiliary/scanner/smb/smb_login"
        "auxiliary/scanner/http/tomcat_mgr_login"
    )
    
    for mod_name in "${{MSF_MODULES[@]}}"; do
        echo ""
        echo "---"
        echo "[*] Exécution du module Metasploit : $mod_name"
        
        # On ne lance le module que si le port correspondant a été trouvé par Nmap
        PORT_CHECK=""
        case "$mod_name" in
            *ftp*) PORT_CHECK=$(grep -c '21/open' /tmp/nmap_grepable.log) ;;
            *vnc*) PORT_CHECK=$(grep -c '5900/open' /tmp/nmap_grepable.log) ;;
            *telnet*) PORT_CHECK=$(grep -c '23/open' /tmp/nmap_grepable.log) ;;
            *rsh*) PORT_CHECK=$(grep -c '514/open' /tmp/nmap_grepable.log) ;;
            *smb*) PORT_CHECK=$(grep -c '445/open' /tmp/nmap_grepable.log) ;;
            *tomcat*) PORT_CHECK=$(grep -c '8080/open' /tmp/nmap_grepable.log) ;;
            *) PORT_CHECK=1 ;; # Pour les autres, on exécute par défaut
        esac

        if [ "$PORT_CHECK" -gt 0 ]; then
            MSF_SCRIPT_CONTENT="use $mod_name\\nsetg RHOSTS {target_quoted}\\nsetg THREADS 10\\nrun\\nexit -y"
            echo -e "$MSF_SCRIPT_CONTENT" | msfconsole -q -r -
        else
            echo "[-] Port non détecté pour $mod_name. Module ignoré."
        fi
    done
    echo "###-SECTION-END: 3. Scan de Failles de Configuration (Metasploit) -###"

    echo "\\n[+] Audit Agressif Terminé."
    """
    return ["bash", "-c", command]
