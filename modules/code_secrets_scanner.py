# modules/code_secrets_scanner.py
import shlex

MODULE = {
    "name": "Code Leak Scanner (Gitleaks)",
    "description": "Recherche des secrets (clés API, mots de passe) exposés publiquement sur GitHub pour une organisation ou un utilisateur.",
    "category": "OSINT",
    "schema": [
        {
            "group_name": "Paramètres du Scan",
            "fields": [
                {
                    "name": "github_target",
                    "type": "string",
                    "placeholder": "Nom de l'organisation ou de l'utilisateur (ex: tesla, microsoft)",
                    "required": True,
                },
                {
                    "name": "scan_depth",
                    "type": "select",
                    "choices": ["quick", "full"],
                    "default": "quick",
                    "description": "Quick: scanne les 10 dépôts les plus récents. Full: scanne tous les dépôts."
                },
            ]
        }
    ],
    "cmd": lambda p: _build_gitleaks_command(p),
}

def _build_gitleaks_command(p: dict) -> list[str]:
    target = shlex.quote(p["github_target"])
    depth = p.get("scan_depth", "quick")
    repo_limit = 10 if depth == "quick" else 1000
    command = f"""
    echo '[+] Recherche des dépôts publics pour "{target}"...'
    REPOS=$(curl -s "https://api.github.com/users/{target}/repos?per_page=100&sort=pushed" | jq -r '.[].clone_url' | head -n {repo_limit})
    
    if [ -z "$REPOS" ]; then
        echo '[!] Aucun dépôt public trouvé pour "{target}".'
        exit 0
    fi
    
    COUNT=$(echo "$REPOS" | wc -l)
    echo "[+] $COUNT dépôts trouvés. Lancement du scan de secrets avec Gitleaks..."
    echo "======================================================================"
    
    for repo_url in $REPOS; do
        echo "\\n[*] Scan du dépôt : $repo_url"
        gitleaks detect --source "$repo_url" --no-banner --report-format json --verbose || true
    done
    
    echo "======================================================================"
    echo "[+] Scan terminé."
    """
    
    return ["bash", "-c", command]
