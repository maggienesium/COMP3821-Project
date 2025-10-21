CC = gcc
CFLAGS = -Wall -O2 -fsanitize=address -g -O0

testParse: testParse.c parseRules.c ../wm.c ../wmpp.c hashTable.c
	$(CC) $(CFLAGS) -o testParse testParse.c parseRules.c ../wm.c ../wmpp.c hashTable.c

%.o: %.c wm.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f testParse