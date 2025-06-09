# modules/intelligence_gathering.py
import shlex

MODULE = {
    "name": "1. Intelligence Gathering",
    "description": "OSINT et Reconnaissance. Combine subfinder, whois, theharvester et dnsenum.",
    "category": "PTES - Phase 2",
    "hidden": False,
    "schema": [
        {
            "name": "target",
            "type": "string",
            "placeholder": "domaine.com",
            "required": True,
        },
        {
            "name": "mode",
            "type": "select",
            "choices": ["quick", "full"],
            "default": "quick",
        },
    ],
    "cmd": lambda p: [
        "bash",
        "-c",
        " && ".join(
            [
                f"echo '[+] Running Subfinder...' && subfinder -d {shlex.quote(p['target'])} || true",
                f"echo '[+] Running Whois...' && whois {shlex.quote(p['target'])} || true",
                # Outils plus longs pour le mode 'full'
                (
                    f"echo '[+] Running TheHarvester...' && theharvester -d {shlex.quote(p['target'])} -b all || true && "
                    f"echo '[+] Running Dnsenum...' && dnsenum {shlex.quote(p['target'])} || true"
                )
                if p["mode"] == "full"
                else "echo '[!] TheHarvester and Dnsenum skipped in quick mode.'",
            ]
        ),
    ],
}
