compile:
	g++ --std=c++14 -Wall -Wextra -lcryptopp -o AES aes-modes.cpp

run:
	./AES
	cat out.txt

pack:
	7z a 0816146.zip aes-modes.cpp out.txt
