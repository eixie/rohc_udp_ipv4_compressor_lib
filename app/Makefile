CC = gcc

#DEBUG = 1
CFLAGS  += -Wall -Wextra 

ifndef DEBUG
CFLAGS	+= -O2 
else
CFLAGS  += -O0 -g -DDEBUG=true
endif
 
INCLUD_DIR = ../include
INCLUDE += -I./ -I$(INCLUD_DIR)/common -I$(INCLUD_DIR)/compress -I$(INCLUD_DIR)/protocol

LINK_DIR  = -L../src

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

default: rohcCompDemo.exe 

$(OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE)  $< -o $@ 

rohcCompDemo.exe: $(OBJS)
	$(CC) $^ -o $@ $(INCLUDE)  $(LINK_DIR) -ludpIpROHCComp -lwsock32

	
.PHONY: clean 	

clean:
	$(RM) $(OBJS) *.exe *.o
	
