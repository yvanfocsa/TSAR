# web/app/modules.py

"""
Chargement dynamique des modules “outils” depuis ../modules
Les MODULES marqués hidden=True sont ignorés,
et les doublons de nom sont automatiquement filtrés.
"""

import importlib.util as iutil
import logging
import sys
import os
from typing import Dict, List, Tuple
import pathlib

MODULES: List[dict] = []  # utilisé par routes.py/get_categories()

# NOUVEAU : Référence à la fonction de reporting_global
_reporting_sections_choices_func = None
_reporting_sections_values_func = None # NOUVEAU : pour les valeurs seules

def load_modules() -> None:
    """
    Parcourt ../modules/*.py, importe chaque module, récupère sa variable MODULE (dict),
    et l’ajoute à MODULES si elle n’est pas cachée et n’existe pas déjà.
    """
    # MODIFIÉ : Vider la liste pour éviter les avertissements de rechargement dans les workers Celery.
    MODULES.clear()

    # Chemin vers ../modules (au même niveau que web/)
    root = pathlib.Path(__file__).resolve().parents[1] / "modules"
    if not root.exists():
        logging.warning("Dossier modules introuvable : %s", root)
        return

    # S’assurer que le dossier modules est dans sys.path
    modules_dir = str(root)
    if modules_dir not in sys.path:
        sys.path.insert(0, modules_dir)

    # Réinitialisation des fonctions de choix de reporting
    global _reporting_sections_choices_func, _reporting_sections_values_func
    _reporting_sections_choices_func = None
    _reporting_sections_values_func = None

    for file in root.rglob("*.py"):
        name = file.stem
        full_module_name = f"modules.{name}"
        spec = iutil.spec_from_file_location(full_module_name, str(file))
        if spec is None or spec.loader is None:
            continue

        mod = iutil.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            
            meta = getattr(mod, "MODULE", None)
            if not isinstance(meta, dict):
                continue

            # Si c'est le module de reporting_global, enregistrer ses fonctions de choix
            if mod.__name__ == 'modules.reporting_global' and hasattr(mod, '_get_report_sections_choices_internal'):
                _reporting_sections_choices_func = mod._get_report_sections_choices_internal
            if mod.__name__ == 'modules.reporting_global' and hasattr(mod, 'REPORT_SECTION_IDS_DEFAULT'):
                # On utilise la variable REPORT_SECTION_IDS_DEFAULT comme une "fonction" pour récupérer les valeurs par défaut
                _reporting_sections_values_func = lambda: mod.REPORT_SECTION_IDS_DEFAULT

            # ignore les modules cachés
            if any(m["name"] == meta["name"] for m in MODULES):
                logging.warning("Module %s déjà chargé, on l’ignore", meta["name"])
                continue

            MODULES.append(meta) 
        except Exception as err:
            logging.error("Erreur import %s : %s", file.name, err, exc_info=True)
            continue

def get_categories() -> Dict[str, List[dict]]:
    """
    Retourne { catégorie: [MODULES triés par name] } pour affichage.
    Ne renvoie pas les modules masqués.
    """
    cats: Dict[str, List[dict]] = {}
    for mod in MODULES:
        if not mod.get("hidden_from_list", False): 
            cats.setdefault(mod["category"], []).append(mod)

    # tri alphabétique dans chaque catégorie
    for lst in cats.values():
        lst.sort(key=lambda x: x["name"].lower())
    return cats

def get_module_by_name(name: str) -> dict | None:
    """
    Recherche un module dans la liste chargée par son nom.
    Peut trouver des modules cachés (hidden_from_list) si nécessaire.
    """
    for mod in MODULES: 
        if mod["name"] == name:
            return mod
    return None

def get_reporting_sections_choices() -> List[Tuple[str, str]]:
    """
    Retourne la liste des choix de sections pour le rapport de synthèse,
    sous forme de paires (valeur, label), obtenue depuis le module reporting_global.
    """
    if _reporting_sections_choices_func:
        return _reporting_sections_choices_func()
    return []

def get_reporting_sections_choices_as_values() -> List[str]:
    """
    Retourne la liste des ID des sections par défaut pour le rapport de synthèse (valeurs internes),
    obtenue depuis le module reporting_global.
    """
    if _reporting_sections_values_func:
        return _reporting_sections_values_func()
    return []
