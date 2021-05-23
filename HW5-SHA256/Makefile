all: clean compile run

compile:
	g++ --std=c++14 -Wall -Wextra -Wconversion -lcryptopp -o sha256 sha256.cpp
	g++ --std=c++14 -Wall -Wextra -Wconversion -lcryptopp -o hashchain hashchain.cpp

clean:
	-rm sha256 hashchain out.txt 0816146.zip

run:
	./sha256
	./hashchain
	cat out.txt

pack:
	7z a 0816146.zip hashchain.cpp out.txt
