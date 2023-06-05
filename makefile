all:
	nasm elf-eater.s -f elf64 -o elf-eater.o
	ld elf-eater.o -o elf-eater
	rm elf-eater.o
	nasm -g scan.s -f elf64 -o scan.o
	ld -g scan.o -o scan
	rm scan.o
	gcc -g inf.c -o inf
clean:
	rm -f *.o clone* elf-eater scan xfiles inf
