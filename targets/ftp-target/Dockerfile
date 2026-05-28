FROM ubuntu:22.04

LABEL description="CTF FTP target – vsftpd backdoor sim + Wazuh agent"

ARG WAZUH_MANAGER=10.0.10.2
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    vsftpd ftp netcat-openbsd python3 \
    curl wget gnupg2 rsyslog \
    && rm -rf /var/lib/apt/lists/*

# ── Install Wazuh agent ───────────────────────────────────
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="${WAZUH_MANAGER}" \
    WAZUH_AGENT_GROUP="ctf-targets" \
    apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# ── vsftpd config ─────────────────────────────────────────
COPY vsftpd.conf /etc/vsftpd.conf

# ── Create FTP users ──────────────────────────────────────
RUN useradd -m ftpuser && echo "ftpuser:ftppass" | chpasswd
RUN mkdir -p /var/ftp/pub && chmod 755 /var/ftp/pub

# ── Plant flags ───────────────────────────────────────────
RUN echo "FLAG{ftp_anonymous_access_0x03}" > /var/ftp/pub/flag.txt
RUN echo "FLAG{ftp_backdoor_shell_0x04}"   > /root/flag.txt

# ── vsftpd 2.3.4 backdoor simulator ──────────────────────
COPY backdoor_listener.py /usr/local/bin/backdoor_listener.py
RUN chmod +x /usr/local/bin/backdoor_listener.py

# ── rsyslog ships vsftpd logs to Wazuh ───────────────────
RUN echo 'module(load="imfile") \n\
input(type="imfile" File="/var/log/vsftpd.log" Tag="vsftpd") \n\
*.* @@'"${WAZUH_MANAGER}"':514' > /etc/rsyslog.d/vsftpd.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21 6200

CMD ["/entrypoint.sh"]
