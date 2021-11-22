build:
	./setup.sh

test:
	gcc -no-pie -o get_address_test.o get_address_test.c && ./get_address_test.o