


gcc -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wcast-align -Wconversion -Wsign-conversion -Wnull-dereference -g3 -O0 -I/usr/include/postgresql/ -c /home/bat/POC-VC/projet/Pam_modules/src/vc_auth_testing.c -o obj/vc_auth_testing.o gcc -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wcast-align -Wconversion -Wsign-conversion -Wnull-dereference -g3 -O0 -I/usr/include/postgresql/ -c /home/bat/POC-VC/projet/Pam_modules/lib/jwt.c -o obj/jwt.o

gcc -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wcast-align -Wconversion -Wsign-conversion -Wnull-dereference -g3 -O0 -I/usr/include/postgresql/ obj/vc_auth_testing.o obj/jwt.o -lpq -lssl -lcrypto -o binex
