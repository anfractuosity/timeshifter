CC=gcc
CFLAGS=-lnetfilter_queue -lnfnetlink -lm

timeshiftermake: timeshifter.c 
	$(CC) -o timeshifter timeshifter.c $(CFLAGS)

clean:
	rm timeshifter
