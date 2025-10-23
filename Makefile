CC = gcc
CFLAGS = -Wall -Wextra -Og -g -Werror \
         -Wshadow -Wpointer-arith -Wcast-align \
         -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
         -Wformat=2 -Wfloat-equal -Wconversion -Wsign-conversion \
         -Winit-self -fsanitize=address -fsanitize=undefined \
         -fno-omit-frame-pointer

SRC_DIR = src
OBJ_DIR = $(SRC_DIR)/WM
TARGET  = $(OBJ_DIR)/wm_test

SRC = $(SRC_DIR)/wm.c $(SRC_DIR)/wmpp.c $(SRC_DIR)/main.c $(SRC_DIR)/bloom.c
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(SRC_DIR)/WM/wm.h
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild
