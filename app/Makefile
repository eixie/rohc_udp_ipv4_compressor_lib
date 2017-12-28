CC = gcc

#DEBUG = 1
CFLAGS  += -Wall -Wextra 

ifndef DEBUG
CFLAGS	+= -O2
else
CFLAGS  += -O0 -g
endif
 
INCLUD_DIR = ../include
INCLUDE += -I./ -I$(INCLUD_DIR)/common -I$(INCLUD_DIR)/compress -I$(INCLUD_DIR)/protocol

LINK_DIR  = -L../src

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)

default: preprocess rohc_build_app.exe postprocess

preprocess:
	mv msys-2.0.dll msys-2.0.dll.x
postprocess:
	mv msys-2.0.dll.x msys-2.0.dll  
$(OBJS): %.o:%.c
	$(CC) -c $(CFLAGS) $(INCLUDE)  $< -o $@ 

rohc_build_app.exe: $(OBJS)
	$(CC) $^ -o $@ $(INCLUDE)  $(LINK_DIR) -lROHCcomp

	
.PHONY: clean 	

clean:
	$(RM) $(OBJS) *.exe *.o
	
