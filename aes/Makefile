
all:libaes.a aes_test

aes_test: aes_test.o aes.o
	gcc -o $@ $^

libaes.a: aes.o
	ar rs $@ $^

%.o:%.c
	gcc -DCONFIG_USE_INTTYPES_H -DCONFIG_INTERNAL_LIBTOMMATH -g -c $<

clean:
	rm -rf *.o libaes.a

