# ==============================================================================
#  Dockerfile pour l'image "toolbox" de TSAR
#  Basé sur Kali Linux et inclut tous les outils de pentest nécessaires.
# ==============================================================================

FROM kalilinux/kali-rolling:latest

# Définir l'environnement comme non interactif pour éviter les prompts
ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------------------
# ÉTAPE 1: Installation des dépendances système et des outils via APT
# ------------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    # Essentiels
    git \
    curl \
    wget \
    unzip \
    jq \
    # Outils Python
    python3 \
    python3-pip \
    python3-shodan \
    # Outils de compilation (pour Go)
    golang-go \
    # Outils de pentest
    nmap \
    whois \
    subfinder \
    dnsenum \
    sqlmap \
    metasploit-framework \
    nikto \
    nuclei \
    gobuster \
    wfuzz \
    whatweb \
    wpscan \
    hydra \
    gvm-tools \
    openvas-scanner \
    amass \
    theharvester \
    neo4j && \
    # Nettoyage
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# ÉTAPE 2: Installation des outils depuis GitHub et autres sources
# ------------------------------------------------------------------------------
# Installation de AD_Miner
RUN git clone https://github.com/AD-Security/AD_Miner.git /opt/AD_Miner && \
    pip3 install --no-cache-dir --break-system-packages --ignore-installed -r /opt/AD_Miner/requirements.txt && \
    ln -s /opt/AD_Miner/ADMiner.py /usr/local/bin/adminer

# Installation de WPProbe (n'a pas de requirements.txt)
RUN git clone https://github.com/Chocapikk/wpprobe.git /opt/wpprobe && \
    ln -s /opt/wpprobe/wpprobe.py /usr/local/bin/wpprobe

# Installation de testssl.sh
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Installation de LinWinPwn
RUN git clone https://github.com/lefayjey/linWinPwn.git /opt/linWinPwn

# Installation de BruteShark (version binaire directe avec le bon nom de fichier)
RUN wget https://github.com/odedshimon/BruteShark/releases/latest/download/BruteSharkCli -O /usr/local/bin/bruteshark && \
    chmod +x /usr/local/bin/bruteshark

# ------------------------------------------------------------------------------
# ÉTAPE 3: Installation des outils Go
# ------------------------------------------------------------------------------
# Configuration des variables d'environnement pour Go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Installation de GoSearch
RUN go install -v github.com/ibnaleem/gosearch@latest

# ------------------------------------------------------------------------------
# ÉTAPE 4: Finalisation
# ------------------------------------------------------------------------------
# Définir le répertoire de travail par défaut
WORKDIR /opt/toolbox
