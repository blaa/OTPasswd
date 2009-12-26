.PHONY: clean all

all: lock suid pam_test

lock: lock.c
	gcc -o $@ -Wall -O0 -ggdb $<

suid: suid.c
	gcc -o $@ -Wall -O0 -ggdb $<
	chmod u+s $@

pam_test: pam_test.c
	gcc -o $@ -Wall -lpam -O0 -ggdb $<

clean:
	rm -f lock suid test_lck *.o
