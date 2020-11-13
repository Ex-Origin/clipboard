SUBDIRS = $(shell find . * -type d | grep -v "\.")

.PHONY:all clean


all:
	@for subdir in $(SUBDIRS); do $(MAKE) -C $$subdir; done
	gcc server.c common.c rsa/libuser_rsa.a aes/libaes.a -g -o server
	gcc $(shell pkg-config --cflags gtk+-3.0) client.c  common.c rsa/libuser_rsa.a aes/libaes.a -g -o client $(shell pkg-config --libs gtk+-3.0)

clean:
	@for subdir in $(SUBDIRS); do $(MAKE) -C $$subdir clean; done


key:
	openssl genrsa -out rsa_private_key.pem 1024
	openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
	xxd -i rsa_private_key.pem > rsa_private_key_pem.h
	xxd -i rsa_public_key.pem > rsa_public_key_pem.h