CC = gcc

CFLAGS  +=  -Wall -Wextra 

ifndef DEBUG
CFLAGS	+= -O2
else
CFLAGS  += -O0 -g -DDEBUG=true
endif

INCLUD_DIR = ../include
INCLUDE += -I$(INCLUD_DIR)/common -I$(INCLUD_DIR)/compress -I$(INCLUD_DIR)/protocol

LDSHFLAGS += ${CFLAGS} -shared -fPIC -Wl,-Bsymbolic

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

default: libudpIpROHCComp.dll

$(OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@ 

libudpIpROHCComp.dll: $(OBJS)
	$(CC) $^ -o $@ $(LDSHFLAGS) 
	cp $@ -r ../app/

	
.PHONY: clean 	

clean:
	$(RM) $(OBJS) *.dll *.o
	
