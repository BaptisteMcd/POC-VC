# syntax=docker/dockerfile:1

# Administration fedora classique
FROM fedora:latest
RUN dnf -y update && dnf -y install make gcc libcurl-devel pam-devel openssl-devel.x86_64 supervisor openssh-server iputils && dnf clean all

RUN mkdir -p /var/run/sshd
RUN mkdir -p /var/run/supervisord

RUN useradd -m -s /bin/bash firstuser
RUN echo "firstuser:nokc" | chpasswd
RUN echo "root:nokc" | chpasswd
ADD ./installation/Client_PostgreSQL/supervisord.conf /etc/supervisord.conf
ADD ./installation/Client_PostgreSQL/kc_auth.conf /etc/kc_auth.conf
# Custom ENV variables, OPTIONAL
ADD ./installation/Client_PostgreSQL/environment /etc/environment 


RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd
RUN touch /tmp/audit.log && chmod 777 /tmp/audit.log


# VariableS ENV À RAJOUTER


# Compiler et installer les shared object PAM custom
RUN mkdir ./Pam_modules
ADD ../../projet/Pam_modules ./Pam_modules
RUN cd ./Pam_modules && make -B

RUN dnf -y install postgresql-server postgresql-contrib && dnf clean all

RUN mkdir /data
RUN chown -R postgres:postgres /data


RUN mkdir /var/run/postgresql/
RUN chown -R postgres:postgres /var/run/postgresql/

USER postgres
RUN initdb -D /data
# RUN pg_ctl -D /data start

# Installation de PostgreSQL
# RUN systemctl enable postgresql
# RUN postgresql-setup --initdb --unit postgresql


USER root



# Copier les fichiers de configuration pam.d afin d'utiliser les PAM custom
ADD ./installation/Client_PostgreSQL/pam_custom /etc/pam.d/su 
ADD ./installation/Client_PostgreSQL/sshd /etc/pam.d/sshd
ADD ./installation/Client_PostgreSQL/pam_pgsql /etc/pam.d/postgresql

# Autoriser l'authentification PAM pour les utilisateurs
RUN sed -i 's|local   all             all                                     trust|local   all             all                                     pam|g' /data/pg_hba.conf


EXPOSE 22 5432
ENTRYPOINT ["/usr/bin/supervisord", "-n"]