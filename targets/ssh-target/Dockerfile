FROM ubuntu:22.04

LABEL description="CTF SSH brute-force target – weak credentials, Wazuh agent installed"

ARG WAZUH_MANAGER=10.0.10.2
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server sudo curl wget gnupg2 \
    net-tools vim rsyslog \
    && rm -rf /var/lib/apt/lists/*

# ── Install Wazuh agent (reports back to existing Wazuh VM) ──
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER="${WAZUH_MANAGER}" \
    WAZUH_AGENT_GROUP="ctf-targets" \
    apt-get install -y wazuh-agent && \
    rm -rf /var/lib/apt/lists/*

# ── Create users with weak passwords ──────────────────────
# admin:admin, ctfuser:password, guest:guest123
RUN useradd -m -s /bin/bash admin    && echo "admin:admin"       | chpasswd && \
    useradd -m -s /bin/bash ctfuser  && echo "ctfuser:password"  | chpasswd && \
    useradd -m -s /bin/bash guest    && echo "guest:guest123"     | chpasswd && \
    usermod -aG sudo admin

# ── SSH: intentionally weak config ────────────────────────
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/'          /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/'                            /etc/ssh/sshd_config && \
    echo "MaxAuthTries 100"  >> /etc/ssh/sshd_config && \
    echo "LogLevel VERBOSE"  >> /etc/ssh/sshd_config

# ── Plant CTF flags ───────────────────────────────────────
RUN echo "FLAG{ssh_brute_force_success_0x01}" > /home/ctfuser/flag.txt && \
    chmod 600 /home/ctfuser/flag.txt && chown ctfuser:ctfuser /home/ctfuser/flag.txt

RUN echo "FLAG{root_privilege_escalation_0x02}" > /root/root_flag.txt && \
    chmod 600 /root/root_flag.txt

# ── SUID binary for priv-esc challenge ────────────────────
RUN cp /usr/bin/vim.basic /usr/local/bin/vim_suid 2>/dev/null || \
    cp /usr/bin/vim /usr/local/bin/vim_suid 2>/dev/null || true && \
    chmod u+s /usr/local/bin/vim_suid 2>/dev/null || true

# ── World-writable cron job (priv-esc vector) ─────────────
COPY backup.sh /usr/local/bin/backup.sh
RUN chmod 777 /usr/local/bin/backup.sh && \
    echo "*/5 * * * * root /usr/local/bin/backup.sh" >> /etc/crontab

# ── Wazuh agent config pointing at external manager ───────
RUN sed -i "s/MANAGER_IP/${WAZUH_MANAGER}/" /var/ossec/etc/ossec.conf || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

CMD ["/entrypoint.sh"]
