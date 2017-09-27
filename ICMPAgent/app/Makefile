CC=gcc 
CFLAGS=-Wall

all: app
app: app.o
app.o: app.c

clean:
	rm -f app app.o
run: app
	./app 127.0.0.1 127.0.0.1 S
