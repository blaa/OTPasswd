.PHONY: clean

lock: lock.c
	gcc -o $@ -Wall -O0 -ggdb $<

suid: suid.c
	gcc -o $@ -Wall -O0 -ggdb $<
	chmod u+s $@

clean:
	rm -f lock suid test_lck *.o
