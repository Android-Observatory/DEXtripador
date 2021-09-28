CC=gcc
AR=ar
CFLAGS=-c -g -Wall
OBJ=obj-files/
OUT=out/
BIN_NAME=elf_parser
STATIC_LIB_NAME=elf_parser.a
SHARED_LIB_NAME=elf_parser.so
HDR=headers/
SRC=src/
PYB=python_binding/

.PHONY: clean remove install

all: dirs $(OUT)$(BIN_NAME) $(OUT)$(STATIC_LIB_NAME) $(OUT)$(SHARED_LIB_NAME)

dirs:
	mkdir -p $(OBJ)
	mkdir -p $(OUT)

$(OUT)$(BIN_NAME): $(OBJ)file_management.o $(OBJ)memory_management.o $(OBJ)elf_parser.o $(OBJ)elf_data_access.o $(OBJ)main.o
	$(CC) -I $(HDR) -o $@ $^

$(OBJ)file_management.o: $(SRC)file_management.c 
	$(CC) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)memory_management.o: $(SRC)memory_management.c 
	$(CC) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)elf_parser.o: $(SRC)elf_parser.c
	$(CC) -I $(HDR) $(CFLAGS) -Wformat=0 -o $@ $<

$(OBJ)elf_data_access.o: $(SRC)elf_data_access.c
	$(CC) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)main.o: main.c
	$(CC) -I $(HDR) $(CFLAGS) -o $@ $<

$(OUT)$(STATIC_LIB_NAME): $(OBJ)file_management.o $(OBJ)memory_management.o $(OBJ)elf_parser.o $(OBJ)elf_data_access.o
	$(AR) -crv $@ $^

$(OUT)$(SHARED_LIB_NAME): $(SRC)file_management.c $(SRC)memory_management.c $(SRC)elf_parser.c $(SRC)elf_data_access.c
	$(CC) -Wl,-soname=$(SHARED_LIB_NAME) -fpic -shared -Wformat=0 -I $(HDR) -o $@ $^
	@cp $(OUT)$(SHARED_LIB_NAME) $(PYB)

########################################################
clean:
	rm -rf $(OBJ)
	rm -rf $(OUT)
	rm $(PYB)$(SHARED_LIB_NAME)

########################################################
remove:
	rm -rf $(OBJ)
	rm -rf $(OUT)
	rm $(PYB)$(SHARED_LIB_NAME)
	sudo rm -f /usr/bin/$(BIN_NAME)

install: dirs $(OUT)$(BIN_NAME)
	@cd $(OUT)
	@echo "Creating symbolic link to $(PWD)/$(OUT)$(BIN_NAME) in /usr/bin (you need to be root)"
	sudo rm -f /usr/bin/$(BIN_NAME)
	sudo ln -s "$(PWD)/$(OUT)$(BIN_NAME)" /usr/bin/$(BIN_NAME)
	@echo "Done"