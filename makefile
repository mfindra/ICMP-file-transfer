NAME= secret
CC= g++
FLAGS= -std=c++11 -pedantic 

all:
	$(CC) $(FLAGS) $(NAME).cpp -o $(NAME) -lpcap

clean:
	rm $(NAME) 