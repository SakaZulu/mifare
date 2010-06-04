CFLAGS=-Wall -O2 -g -I /home/arkusuma/Projects/acr120

all: test/select test/read test/write

test/select: test/select.o acr120.o

test/read: test/read.o acr120.o

test/write: test/write.o acr120.o

acr120.o:

clean:
	rm -f *.o test/*.o test/select test/read test/write
