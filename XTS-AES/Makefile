# Makefile for AES C code #


IDIR =.

CC=gcc -g -lstdc++
#CFLAGS=-I$(IDIR) -fPIC -include "stdlib.h" -include "string.h" -Wno-write-strings -std=c++0x
CFLAGS=-I$(IDIR) -fPIC -include "stdlib.h" -include "string.h" -Wno-write-strings

LIBS=-lm

_DEPS = AES.h XTS_AES.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ_D = AES.o XTS_AES.o main.o
OBJ_D = $(patsubst %,%,$(_OBJ_D))

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: test_AES 

test_AES: $(OBJ_D) 
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)



.PHONY: clean 

clean:
	rm -f *.so *.o *~ test_AES 
