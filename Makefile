CFLAGS=-Werror -Wall -ansi
LDFLAGS=
EXEC=jchroot

all: $(EXEC)

jchroot: jchroot.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm *.o $(EXEC)


.PHONY: clean
