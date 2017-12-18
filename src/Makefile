CC = gcc

#DEBUG = 1
CFLAGS  += -fPIC -Wall -Wextra 

ifndef DEBUG
CFLAGS	+= -O2
else
CFLAGS  += -O0 -g
endif

INCLUD_DIR = ../include
INCLUDE += -I$(INCLUD_DIR)/common -I$(INCLUD_DIR)/compress -I$(INCLUD_DIR)/protocol

LDSHFLAGS += ${CFLAGS} -shared -Wl,-Bsymbolic -Wl,-rpath

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

default: libROHCcomp.dll

$(OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@ 

libROHCcomp.dll: $(OBJS)
	$(CC) $^ -o $@ $(LDSHFLAGS) 

	
.PHONY: clean 	

clean:
	$(RM) $(OBJS) *.dll *.o
	
