CC = gcc
CFLAGS = -fPIC -lcurl -ljwt -ljansson -g
LDFLAGS = -lcurl -ljwt -ljansson

SRC_DIR = ./src
OBJ_DIR = ./obj

SRC_FILES := kc_auth.c logger.c main.c
OBJ_FILES := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

TARGET = /lib64/security/pam_custom.so

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	sudo ld $(LDFLAGS) -x --shared -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

SRC_FILES2 := kc_auth.c logger.c main_pg.c
OBJ_FILES2 := $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES2))
TARGET2 = /lib64/security/pam_cpgsql.so
all: $(TARGET2)
	
$(TARGET2): $(OBJ_FILES2)
	sudo ld $(LDFLAGS) -x --shared -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_FILES2)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ_DIR)/*.o $(TARGET) $(TARGET2)