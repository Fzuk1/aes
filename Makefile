CC = gcc
CFLAGS = -Wall -Wextra -g -I src/include 

all: aes

aes: src/*.c
	@${CC} $^ -o $@ ${CFLAGS}

