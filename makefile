AUTHOR= xfindr00
NAME= secret
CC= g++
FLAGS= -std=c++11 -lpcap -lssl -lcrypto -pedantic

all:
	$(CC) $(NAME).cpp -o $(NAME) $(FLAGS)  

clean:
	rm $(NAME)
	rm *.out

pack: 
	tar -cf $(AUTHOR).tar manual.pdf secret.cpp makefile secret.1