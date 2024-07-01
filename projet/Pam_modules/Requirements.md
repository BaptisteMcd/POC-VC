Libraries : 
Libcurl Curl : curl/curl.h
Libpq PostgreSQL : libpq-fe.h
Libpam PAM : security/pam_modules.h

Depending on your distribution the directory of PAM shared object, may vary.
Redhat based : /lib/security/
Debian : /lib/x86_64-linux-gnu/security/

sudo apt install -y make gcc libcurl4-openssl-dev libpam0g-dev libssl-dev supervisor openssh-server iputils-ping libpq-dev postgresql postgresql-contrib