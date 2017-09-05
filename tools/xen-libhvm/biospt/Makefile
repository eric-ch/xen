PROG=	biospt
SRCS=	biospt.c

CFLAGS+= -Wall -g -D_LINUX -Wstrict-prototypes

all: $(PROG)

$(PROG) : $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(PROG) -lxenhvm

CLEANFILES= $(PROG)

clean :
	rm -f $(CLEANFILES) $(patsubst %.c,%.o, $(SRCS))
