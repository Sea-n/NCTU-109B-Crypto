compile:
	g++ --std=c++14 -Wall -Wextra -lcryptopp -o AES aes-modes.cpp

onsite:
	g++ --std=c++14 -Wall -Wextra -lcryptopp -o onsite onsite.cpp
	g++ --std=c++14 -Wall -Wextra -lcryptopp -o onsite-verify onsite-verify.cpp

clean:
	-rm AES
	-rm onsite onsite-verify

run:
	./AES
	cat out.txt

pack:
	7z a 0816146.zip aes-modes.cpp out.txt
