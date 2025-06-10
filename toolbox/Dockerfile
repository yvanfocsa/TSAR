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

# Installation de GoSearch
RUN go install -v github.com/ibnaleem/gosearch@latest


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
# FIX: Toutes les commandes sur une seule ligne pour éviter les erreurs de parsing.
RUN apt-get update && apt-get install -y --no-install-recommends git curl wget unzip jq python3 python3-pip python3-shodan nmap whois subfinder dnsenum sqlmap metasploit-framework nikto nuclei gobuster wfuzz whatweb wpscan hydra gvm-tools openvas-scanner amass theharvester neo4j wireguard-tools && apt-get clean && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# Installation des outils depuis GitHub et autres sources
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

# Installation de BruteShark (version binaire directe)
RUN wget https://github.com/odedshimon/BruteShark/releases/latest/download/BruteSharkCli -O /usr/local/bin/bruteshark && \
    chmod +x /usr/local/bin/bruteshark

# ------------------------------------------------------------------------------
# Copie des outils Go compilés depuis le builder
# ------------------------------------------------------------------------------
COPY --from=go-builder /go/bin/gosearch /usr/local/bin/gosearch

# ------------------------------------------------------------------------------
# Finalisation
# ------------------------------------------------------------------------------
# Définir le répertoire de travail par défaut
WORKDIR /opt/toolbox
