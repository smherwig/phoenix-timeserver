INCLUDES=-I $(HOME)/include
STATIC_LIBS= $(addprefix $(HOME)/lib/, librho.a)

CPPFLAGS= $(INCLUDES)
CFLAGS= -Wall -Werror -Wextra
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS = \
	   tntserver.o

tntserver: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

tntserver.o: tntserver.c

clean:
	rm -f tntserver $(OBJS)

.PHONY: clean
