
pppv3: pppv3.c crypto.c crypto.h num.c num.h
	gcc -o $@ -Wall -lgmp -lssl $< crypto.c num.c
