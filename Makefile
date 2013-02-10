PROGS =  commitment_req commitment_chk
CFLAGS = -g -I. -lcrypto
CC = gcc
CLEANFILES = commitment_common.o

all: ${PROGS}

commitment_req: commitment_common.o
	${CC} ${CFLAGS} commitment_req.c commitment_common.o -o commitment_req

commitment_chk: commitment_common.o
	${CC} ${CFLAGS} commitment_chk.c commitment_common.o -o commitment_chk

commitment_common.o: 
	${CC} ${CFLAGS} -c commitment_common.c commitment_common.h

clean:
	rm -f ${CLEANFILES}
	rm -f ${PROGS}

