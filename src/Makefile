CC = gcc
CFLAGS = -Wall -O2

SRC = wm.c wmpp.c main.c bloom.c
OBJ = $(SRC:.c=.o)
TARGET = wm_test

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c wm.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJ) $(TARGET)

rebuild: clean $(TARGET)

.PHONY: clean rebuild
