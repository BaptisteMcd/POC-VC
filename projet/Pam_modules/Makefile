install : custom pgsql vc pg_vc

CC = gcc
CFLAGS = -fPIC -Wall -lcurl -I/usr/include/postgresql/ -lpq  -lssl -lcrypto
LDFLAGS = -lcurl -lssl -lpq -lcrypto

SRC_DIR = ./src
OBJ_DIR = ./obj
LIB_DIR = ./lib

SRC_FILES := dump.c error.c hashtable.c hashtable_seed.c kc_auth.c load.c logger.c main.c main_pg.c main_vc.c main_pg_vc.c memory.c pack_unpack.c strbuffer.c strconv.c utf.c value.c version.c jwt.c jwt-openssl.c base64.c b64.c vc_auth_testing.c
OBJ_FILES := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

# Compile librairies 
$(OBJ_DIR)/%.o: $(LIB_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $< -lm

# Compile sources
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<


# Pam custom for linux authentication
# PAM .so directory, depends on your distribution 
PAM_SO_DIR = /lib/x86_64-linux-gnu/security
#PAM_SO_DIR = /lib64/security


TARGET = $(PAM_SO_DIR)/pam_custom.so
custom: $(TARGET)
$(TARGET): $(OBJ_FILES)
	ld $(LDFLAGS) obj/main.o obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o  obj/jwt.o obj/jwt-openssl.o obj/base64.o obj/b64.o -x --shared -o $(TARGET)


# Pam custom for postgresql authentication
TARGET2 = $(PAM_SO_DIR)/pam_cpgsql.so
pgsql: $(TARGET2)
$(TARGET2): $(OBJ_FILES)
	ld $(LDFLAGS) obj/main_pg.o obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o obj/jwt.o obj/jwt-openssl.o obj/base64.o obj/b64.o -x --shared -o $(TARGET2)

# Pam custom for verifiable credentials (SD-JWT) authentication
TARGET3 = $(PAM_SO_DIR)/pam_vc.so
vc: $(TARGET3)
$(TARGET3): $(OBJ_FILES)
	ld $(LDFLAGS) obj/main_vc.o obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o obj/jwt.o obj/jwt-openssl.o obj/base64.o obj/b64.o -x --shared -o $(TARGET3)

TARGET4 = $(PAM_SO_DIR)/pam_pg_vc.so
pg_vc: $(TARGET4)
$(TARGET4): $(OBJ_FILES)
	ld $(LDFLAGS) obj/main_pg_vc.o obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o obj/jwt.o obj/jwt-openssl.o obj/base64.o obj/b64.o -x --shared -o $(TARGET4)

vc_test:
	gcc -o vc_testing obj/vc_auth_testing.o obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o obj/jwt.o obj/jwt-openssl.o obj/base64.o obj/b64.o $(LDFLAGS) -lpthread

clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET) $(TARGET2) $(TARGET3) $(TARGET3)