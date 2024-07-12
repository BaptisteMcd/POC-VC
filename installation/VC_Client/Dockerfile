# syntax=docker/dockerfile:0

# Administration fedora classique
FROM debian:latest
#RUN dnf -y update && dnf -y install make gcc libcurl-devel pam-devel openssl-devel.x86_64 supervisor openssh-server iputils libpq-devel postgresql-server postgresql-contrib && dnf clean all
RUN apt update && apt upgrade -y && apt install -y make gcc libcurl4-openssl-dev libpam0g-dev libssl-dev supervisor openssh-server iputils-ping libpq-dev postgresql postgresql-contrib vim && apt autoremove -y && apt clean

RUN mkdir -p /var/run/sshd
RUN mkdir -p /var/run/supervisord

RUN useradd -m -s /bin/bash toto
RUN echo "toto:nokc" | chpasswd
RUN echo "root:nokc" | chpasswd
ADD ./installation/VC_Client/supervisord.conf /etc/supervisord.conf
ADD ./installation/VC_Client/kc_auth.conf /etc/kc_auth.conf
ADD ./installation/VC_Client/keycloak_verifiable-credentials.pem /etc/ssl/certs/keycloak_verifiable-credentials.pem
# Custom ENV variables, OPTIONAL
# ADD ./installation/VC_Client/environment /etc/environment 

# RUN ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
RUN sed -i 's|session    required     pam_loginuid.so|session    optional     pam_loginuid.so|g' /etc/pam.d/sshd
RUN touch /tmp/audit.log && chmod 777 /tmp/audit.log

# Compile and install our shared objects for PAM authenfications
RUN mkdir ./Pam_modules
ADD ./projet/Pam_modules ./Pam_modules
RUN cd ./Pam_modules && make -B

RUN mkdir /data 
#/var/run/postgresql/
ADD ./installation/VC_Client/init.sql /docker-entrypoint-initdb.d/init.sql

RUN chown -R postgres:postgres /data /var/run/postgresql/ /docker-entrypoint-initdb.d/

# Init PostgreSQL as postgres
#USER postgres
#RUN initdb -D /data
#USER root

# Copy and replace PAM config files for our authentification methods
ADD ./installation/VC_Client/PAM/* /etc/pam.d/
RUN sed -i 's/^KbdInteractiveAuthentication\s*no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config


# Use PAM with all authentifcation methods in PostgreSQL
#RUN sed -i 's|local   all             all                                     trust|local   all             all                                     pam|g' /data/pg_hba.conf

EXPOSE 22 5432
ENTRYPOINT ["/usr/bin/supervisord", "-n"]
