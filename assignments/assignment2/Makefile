# Makefile for Week 2 Assignment - backdoor web server

CC = gcc
CFLAGS = -g -Wall -Werror -O0

TARGET = normal_web_server

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

.PHONY: clean

clean:
	@rm -f $(TARGET)
