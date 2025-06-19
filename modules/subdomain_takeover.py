# modules/subdomain_takeover.py
import shlex

MODULE = {
    "name": "Subdomain Takeover Scan",
    "description": "Détecte les sous-domaines vulnérables à une prise de contrôle (takeover) en vérifiant les enregistrements CNAME pointant vers des services tiers expirés.",
    "category": "Web",
    "schema": [
        {
            "group_name": "Paramètres du Scan",
            "fields": [
                {
                    "name": "target",
                    "type": "string",
                    "placeholder": "domaine.com",
                    "required": True,
                },
            ]
        }
    ],
    "cmd": lambda p: _build_command(p),
}

def _build_command(p: dict) -> list[str]:
    target = shlex.quote(p["target"])
    
    command = f"""
    echo '[+] Recherche des sous-domaines pour {target}...'
    SUBS=$(subfinder -d {target} -silent)
    
    if [ -z "$SUBS" ]; then
        echo '[!] Aucun sous-domaine trouvé pour {target}.'
        exit 0
    fi
    
    COUNT=$(echo "$SUBS" | wc -l | xargs)
    echo "[+] {{COUNT}} sous-domaines trouvés."
    echo "======================================================================"
    
    echo "Liste des sous-domaines analysés :"
    echo "$SUBS"
    echo ""

    echo "[+] Lancement de Nuclei pour la détection de takeover..."
    # On capture la sortie de Nuclei dans une variable
    NUCLEI_OUTPUT=$(echo "$SUBS" | nuclei -t takeovers/ -no-color -stats -no-interactsh)
    
    # On affiche la sortie brute de Nuclei pour les détails
    echo "$NUCLEI_OUTPUT"
    
    echo "======================================================================"
    echo "[+] Analyse des résultats..."
    
    # On vérifie si la sortie contient des lignes de résultats positifs.
    # Les résultats de Nuclei contiennent généralement le nom du template et la sévérité.
    # MODIFIÉ : Correction de l'expression régulière pour être compatible avec Python et Bash
    if echo "$NUCLEI_OUTPUT" | grep -q -E '\\[(high|critical)\\]'; then
        echo "[CONCLUSION] : VULNÉRABILITÉS TROUVÉES !"
        echo "Le scan a détecté un ou plusieurs sous-domaines potentiellement vulnérables à un takeover."
        echo "Veuillez examiner les lignes contenant '[high]' ou '[critical]' dans la sortie ci-dessus pour identifier les cibles affectées."
    else
        echo "[CONCLUSION] : AUCUNE VULNÉRABILITÉ TROUVÉE."
        echo "Le scan s'est terminé sans détecter de vulnérabilité de type 'subdomain takeover' sur les cibles analysées."
    fi
    
    echo "======================================================================"
    echo "[+] Scan terminé."
    """
    
    return ["bash", "-c", command]
