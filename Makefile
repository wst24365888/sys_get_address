build:
	./setup.sh

get_address_between_threads:
	gcc -no-pie -o get_address_between_threads.o get_address_between_threads.c -lpthread && ./get_address_between_threads.o

get_address_between_procs:
	gcc -no-pie -o ./get_address_between_procs.o ./get_address_between_procs.c && ./get_address_between_procs &
