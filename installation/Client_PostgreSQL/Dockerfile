# syntax=docker/dockerfile:1

# Administration fedora classique
FROM fedora:latest
RUN dnf -y update && dnf -y install make gcc libcurl-devel pam-devel openssl-devel.x86_64 supervisor openssh-server iputils libpq-devel postgresql-server postgresql-contrib && dnf clean all

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

# Compile and install our shared objects for PAM authenfications
RUN mkdir ./Pam_modules
ADD ../../projet/Pam_modules ./Pam_modules
RUN cd ./Pam_modules && make -B

RUN mkdir /data /var/run/postgresql/
ADD ./installation/Client_PostgreSQL/init.sql /docker-entrypoint-initdb.d/init.sql


RUN chown -R postgres:postgres /data /var/run/postgresql/ /docker-entrypoint-initdb.d/

# Init PostgreSQL as postgres
USER postgres
RUN initdb -D /data
USER root

# Copy and replace PAM config files for our authentification methods
ADD ./installation/Client_PostgreSQL/PAM/* /etc/pam.d/


# Use PAM with all authentifcation methods in PostgreSQL
RUN sed -i 's|local   all             all                                     trust|local   all             all                                     pam|g' /data/pg_hba.conf

EXPOSE 22 5432
ENTRYPOINT ["/usr/bin/supervisord", "-n"]