# modules/metasploit_scan.py
import shlex

MODULE = {
    "name": "Metasploit - Scan d'Exploits Potentiels",
    "description": "Utilise les modules auxiliaires de Metasploit pour découvrir des vulnérabilités et extraire les CVEs associées. Ne lance pas d'exploits.",
    "category": "Scan Réseau",
    "hidden_from_list": True,
    "schema": [
        {
            "group_name": "Paramètres du Scan Metasploit",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "Ex: 192.168.1.5 ou 192.168.1.0/24",
                    "required": True,
                    "description": "L'adresse IP ou la plage CIDR à scanner.",
                },
                {
                    "name": "scan_type",
                    "type": "select",
                    "choices": ["quick", "full"],
                    "default": "quick",
                    "description": "Quick: Lance une sélection de modules rapides et courants. Full: Lance une batterie plus large de scanners auxiliaires (plus long).",
                },
                {
                    "name": "threads",
                    "type": "string",
                    "placeholder": "10",
                    "default": "10",
                    "required": True,
                    "description": "Nombre de threads concurrents pour le scan.",
                },
            ],
        }
    ],
    "cmd": lambda p: _build_command(p),
}


def _build_command(p: dict) -> list[str]:
    target_quoted = shlex.quote(p["target"])
    threads = shlex.quote(p.get("threads", "10"))
    scan_type = p.get("scan_type", "quick")

    quick_modules = [
        "auxiliary/scanner/ftp/anonymous",
        "auxiliary/scanner/smb/smb_version",
        "auxiliary/scanner/ssh/ssh_version",
        "auxiliary/scanner/http/title",
        "auxiliary/scanner/vnc/vnc_login",
        "auxiliary/scanner/telnet/telnet_version",
    ]
    full_modules = quick_modules + [
        "auxiliary/scanner/smb/smb_enumshares",
        "auxiliary/scanner/snmp/snmp_enum",
        "auxiliary/scanner/http/options",
        "auxiliary/scanner/http/robots_txt",
        "auxiliary/scanner/pop3/pop3_version",
        "auxiliary/scanner/imap/imap_version",
        "auxiliary/scanner/smtp/smtp_version",
        "auxiliary/scanner/rservices/rsh_login",
        "auxiliary/scanner/http/dir_scanner",
    ]

    modules_to_run = full_modules if scan_type == "full" else quick_modules

    # MODIFIÉ : Nouvelle logique de script beaucoup plus robuste
    command = f"""
    set -e
    
    echo "[+] Démarrage du service de base de données PostgreSQL..."
    service postgresql start || echo "Service PostgreSQL déjà démarré."
    
    # Fichiers temporaires pour les résultats
    SCAN_RESULTS_FILE="/tmp/msf_scan_results.log"
    CVE_RESULTS_FILE="/tmp/msf_cve_results.log"
    echo "" > $SCAN_RESULTS_FILE
    echo "" > $CVE_RESULTS_FILE

    # Boucle sur chaque module
    for mod_name in {' '.join(modules_to_run)}; do
        echo ""
        echo "---"
        echo "[*] Exécution du module : $mod_name"

        # Création du script .rc pour un seul module
        MSF_SCRIPT_CONTENT="use $mod_name\\nsetg RHOSTS {target_quoted}\\nsetg THREADS {threads}\\nrun\\nexit -y"
        
        # Exécution et capture de la sortie
        MODULE_OUTPUT=$(echo -e "$MSF_SCRIPT_CONTENT" | msfconsole -q -r -)
        
        # Affichage de la sortie du module
        echo "$MODULE_OUTPUT"
        
        # Si le module a trouvé quelque chose (contient un '[+]'), on cherche les CVEs
        if echo "$MODULE_OUTPUT" | grep -q '\\[+\\]'; then
            echo "[+] Succès détecté pour $mod_name. Recherche des informations CVE..."
            
            # Script pour la commande 'info'
            INFO_SCRIPT_CONTENT="info $mod_name\\nexit -y"
            INFO_OUTPUT=$(echo -e "$INFO_SCRIPT_CONTENT" | msfconsole -q -r -)
            
            # On ajoute les résultats aux fichiers de log
            echo "\\n\\n###-SECTION-START: Scan - $mod_name -###" >> $SCAN_RESULTS_FILE
            echo "$MODULE_OUTPUT" >> $SCAN_RESULTS_FILE
            echo "###-SECTION-END: Scan - $mod_name -###" >> $SCAN_RESULTS_FILE
            
            echo "\\n\\n###-SECTION-START: CVEs pour $mod_name -###" >> $CVE_RESULTS_FILE
            echo "$INFO_OUTPUT" >> $CVE_RESULTS_FILE
            echo "###-SECTION-END: CVEs pour $mod_name -###" >> $CVE_RESULTS_FILE
        fi
    done
    
    echo ""
    echo "======================================================================"
    echo "                  RÉSUMÉ DES SCANS COMPLETS"
    echo "======================================================================"
    cat $SCAN_RESULTS_FILE
    
    echo ""
    echo "======================================================================"
    echo "                  RÉSUMÉ DES CVEs TROUVÉES"
    echo "======================================================================"
    cat $CVE_RESULTS_FILE
    
    echo "[+] Scan Metasploit terminé."
    """

    return ["bash", "-c", command]
