all: hw3 hw3+

hw3:hw3.cpp
	g++ hw3.cpp -o hw3 -lpcap

hw3+:hw3+.cpp
	g++ hw3+.cpp -o hw3+ -lpcap

clean:
	rm hw3 hw3+
