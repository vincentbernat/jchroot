CFLAGS=-Werror -Wall -ansi
LDFLAGS=
EXEC=jchroot

all: $(EXEC)

jchroot: jchroot.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(EXEC)


.PHONY: clean
