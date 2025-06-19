# ==============================================================================
#  ÉTAPE 1: BUILDER GO
#  Stage temporaire pour compiler les outils Go sans alourdir l'image finale.
# ==============================================================================
FROM kalilinux/kali-rolling:latest AS go-builder

# FIX: Toutes les commandes sur une seule ligne pour éviter les erreurs de parsing.
RUN apt-get update && apt-get install -y --no-install-recommends golang-go ca-certificates git && update-ca-certificates && apt-get clean && rm -rf /var/lib/apt/lists/*

# Configuration de l'environnement Go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH
ENV GOPROXY=direct

# Installation des dernières versions des outils de Project Discovery
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && go install -v github.com/ibnaleem/gosearch@latest


# ==============================================================================
#  ÉTAPE 2: IMAGE FINALE
#  Construction de l'image principale avec tous les outils de pentest.
# ==============================================================================
FROM kalilinux/kali-rolling:latest

# Définir l'environnement comme non interactif pour éviter les prompts
ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------------------
# Installation des dépendances système et des outils via APT
# ------------------------------------------------------------------------------
# CETTE LIGNE EST MAINTENANT TRÈS LONGUE POUR ÉVITER LES ERREURS DE PARSING DES \
RUN apt-get update && apt-get install -y --no-install-recommends git curl wget unzip jq python3 python3-pip python3-shodan nmap whois dnsenum sqlmap metasploit-framework postgresql nikto gobuster wfuzz whatweb wpscan hydra gvm-tools openvas-scanner amass theharvester neo4j wireguard-tools gitleaks python3-requests arp-scan enum4linux-ng nbtscan iproute2 iptables && apt-get clean && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# Installation des outils depuis GitHub et autres sources (avec RUN explicite)
# ------------------------------------------------------------------------------
# Installation de testssl.sh
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Installation de LinWinPwn
RUN git clone https://github.com/lefayjey/linWinPwn.git /opt/linWinPwn

# Installation de BruteShark (version binaire directe)
RUN wget https://github.com/odedshimon/BruteShark/releases/latest/download/BruteSharkCli -O /usr/local/bin/bruteshark && chmod +x /usr/local/bin/bruteshark

# ------------------------------------------------------------------------------
# Copie des outils Go compilés depuis le builder
# ------------------------------------------------------------------------------
COPY --from=go-builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=go-builder /go/bin/gosearch /usr/local/bin/gosearch

# ------------------------------------------------------------------------------
# Finalisation
# ------------------------------------------------------------------------------
# Pré-téléchargement des templates Nuclei pour éviter l'attente au premier lancement
RUN nuclei -update-templates

# MODIFIÉ : Initialisation de la base de données Metasploit de manière compatible avec Docker
RUN service postgresql start && sleep 2 && msfdb init && service postgresql stop

# Définir le répertoire de travail par défaut
WORKDIR /opt/toolbox