elf-eater:
	nasm elf-eater.s -f elf64 -o elf-eater.o
	ld elf-eater.o -o elf-eater
	rm elf-eater.o

all:
	elf-eater

clean:
	rm -f *.o clone* elf-eater
