# Mozilla Public License (MPL) Version 2.0.
#
# Copyright (c) 2024 Tijme Gommers (@tijme).
#
# This source code file is part of Relocatable. Relocatable is 
# licensed under Mozilla Public License (MPL) Version 2.0, and 
# you are free to use, modify, and distribute this file under 
# its terms. However, any modified versions of this file must 
# include this same license and copyright notice.

CC_X64 := x86_64-w64-mingw32-gcc
LD_X64 := x86_64-w64-mingw32-ld
OC_X64 := x86_64-w64-mingw32-objcopy
TARGET := relocatable

.PHONY: all clean ./dst/$(TARGET).x64.o ./dst/$(TARGET).x64.elf ./dst/$(TARGET).x64.bin 

all: ./dst/$(TARGET).x64.bin 

clean:
	rm -f ./dst/$(TARGET).*
	
./dst/$(TARGET).x64.o:
	$(CC_X64) -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -Wall -nostdlib -fno-builtin -c ./src/main.c -o ./dst/$(TARGET).x64.o

./dst/$(TARGET).x64.elf: ./dst/$(TARGET).x64.o
	$(LD_X64) -Ttext 0x0 -nostdlib --no-seh --no-dynamic-linker ./dst/$(TARGET).x64.o -o ./dst/$(TARGET).x64.elf

./dst/$(TARGET).x64.bin: ./dst/$(TARGET).x64.elf
	$(OC_X64) -O binary -j .text ./dst/$(TARGET).x64.elf ./dst/$(TARGET).x64.bin
	rm -f ./dst/$(TARGET).x64.elf
	rm -f ./dst/$(TARGET).x64.o