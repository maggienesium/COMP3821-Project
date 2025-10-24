CC = gcc
CFLAGS = -Wall -Wextra -Og -g -Werror \
         -Wshadow -Wpointer-arith -Wcast-align \
         -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
         -Wformat=2 -Wfloat-equal -Wconversion -Wsign-conversion \
         -Winit-self -fsanitize=address -fsanitize=undefined \
         -fno-omit-frame-pointer

SRC_DIR = src
PARSE_DIR = $(SRC_DIR)/parse
WM_DIR = $(SRC_DIR)/WM
BIN_DIR = bin
TOOLS_DIR = tools

TARGET = $(BIN_DIR)/testParse

SRC = $(PARSE_DIR)/parseRules.c \
      $(PARSE_DIR)/main.c \
      $(WM_DIR)/bloom.c \
      $(WM_DIR)/wm.c \
      $(WM_DIR)/wmpp.c

OBJ = $(SRC:.c=.o)

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(OBJ) -lm

# Compile
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run cpplint across all C and header files in src/
LINT = cpplint
LINT_FLAGS = --recursive --quiet

lint:
	@echo "Running cpplint..."
	@$(LINT) $(LINT_FLAGS) $(SRC_DIR)
	@echo "cpplint completed."


clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean all

.PHONY: all clean rebuild lint
