NAME= secret
CC= g++
FLAGS= -std=c++11 -lpcap -lssl -lcrypto -pedantic

all:
	$(CC) $(NAME).cpp -o $(NAME) $(FLAGS)  

clean:
	rm $(NAME) 