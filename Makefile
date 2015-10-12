all:
	gcc -m32 -fno-stack-protector -z execstack -o printf printf.c
	gcc -m32 -fno-stack-protector -z execstack -o gets-overflow gets-overflow.c
	gcc -m32 -fno-stack-protector -z execstack -o strcpy-overflow strcpy-overflow.c
