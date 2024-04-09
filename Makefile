CC = gcc

.PHONY: all
all: main rijndael.so

main: main.c rijndael.o
	$(CC) -o main main.c rijndael.o

rijndael.o: rijndael.c rijndael.h
	$(CC) -o rijndael.o -fPIC -c rijndael.c

rijndael.so: rijndael.o
	$(CC) -o rijndael.so -shared rijndael.o

clean:
	rm -f *.o *.so main
	