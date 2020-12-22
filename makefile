all: hw3

hw3:hw3.c
	g++ hw3.c -o hw3 -lpcap

clean:
	rm hw3
