CC = gcc
CFLAGS = -fPIC -lcurl -lpq
LDFLAGS = -lcurl -lpq

SRC_DIR = ./src
OBJ_DIR = ./obj
LIB_DIR = ./lib

SRC_FILES := dump.c error.c hashtable.c hashtable_seed.c kc_auth.c load.c logger.c main.c main_pg.c memory.c pack_unpack.c strbuffer.c strconv.c utf.c value.c version.c jwt.c jwt-openssl.c base64.c
OBJ_FILES := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

# Compile librairies 
$(OBJ_DIR)/%.o: $(LIB_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile in src
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<



# Pam custom for linux authentication
TARGET = /lib64/security/pam_custom.so
all: $(TARGET)
$(TARGET): $(OBJ_FILES)
	sudo ld -lcurl -lssl -lpq -lcrypto obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/main.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o  obj/jwt.o obj/jwt-openssl.o obj/base64.o -x --shared -o $(TARGET)


# Pam custom for postgresql authentication
TARGET2 = /lib64/security/pam_cpgsql.so
all: $(TARGET2)
$(TARGET2): $(OBJ_FILES)
	sudo ld -lcurl -lssl -lpq -lcrypto obj/dump.o obj/error.o obj/hashtable.o obj/hashtable_seed.o obj/kc_auth.o obj/load.o obj/logger.o obj/main_pg.o obj/memory.o obj/pack_unpack.o obj/strbuffer.o obj/strconv.o obj/utf.o obj/value.o obj/version.o obj/jwt.o obj/jwt-openssl.o obj/base64.o  -x --shared -o $(TARGET2)


clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET) $(TARGET2)