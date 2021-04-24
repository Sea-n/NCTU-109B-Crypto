compile:
	g++ --std=c++14 -Wall -Wextra -Wconversion -lcryptopp -o RSA rsa.cpp

clean:
	-rm RSA
	-rm out.txt
	-rm 0816146.zip

run:
	./RSA
	cat out.txt

pack:
	7z a 0816146.zip rsa.cpp out.txt
