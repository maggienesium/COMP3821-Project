CC = gcc
CFLAGS = -Wall -O2 -fsanitize=address -g -O0

bm: bm.c ../WM/wm.c ../../parse/analytics.c ../../parse/parseRules.c ../WM/wmpp.c ../WM/bloom.c
	$(CC) $(CFLAGS) -o bm bm.c ../WM/wm.c ../../parse/analytics.c ../../parse/parseRules.c ../WM/wmpp.c ../WM/bloom.c

%.o: %.c bm.h 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f bm