CC := x86_64-w64-mingw32-gcc
WINDRES := x86_64-w64-mingw32-windres
STRIP := x86_64-w64-mingw32-strip
OBJCOPY := x86_64-w64-mingw32-objcopy
NM := x86_64-w64-mingw32-nm
PYTHON := python3

SECTION_NAME := .packed

SRC_DIR := src
INC_DIR := include
LIB_DIR := lib
BUILD_DIR := build
BIN_DIR := bin

ifneq ($(FILE),)
    FILE_NAME_ONLY := $(basename $(notdir $(FILE)))
    TARGET := $(BIN_DIR)/$(FILE_NAME_ONLY)_packed.exe
else
    TARGET := $(BIN_DIR)/$(NAME)_$(VERSION)_x64.exe
endif

SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

ifneq ($(FILE),)
    PACKED_OBJ := $(BUILD_DIR)/packed.o
    OBJS += $(PACKED_OBJ)
endif

INC_DIRS := $(shell find $(INC_DIR) -type d)
INCLUDES := $(addprefix -I,$(INC_DIRS))

LIB_DIRS := $(shell find $(LIB_DIR) -type d)
LIB_PATHS := $(addprefix -L,$(LIB_DIRS))

CFLAGS := -O2 -Wall -Wextra $(INCLUDES)
LDFLAGS := $(LIB_PATHS)
LDLIBS := -lcrypt32

.PHONY: all do_build strip clean $(BUILD_DIR)/packed.o

all: clean
	@$(MAKE) do_build
	@$(MAKE) strip

do_build: $(TARGET)

$(TARGET): $(OBJS)
ifeq ($(FILE),)
	$(error FILE argument is required. Usage: make FILE=path/to/file)
endif
	@mkdir -p $(BIN_DIR)
	$(CC) $(OBJS) $(LDFLAGS) $(LDLIBS) -o $@
	@echo "Build Success: $(TARGET)"

$(BUILD_DIR)/packed.o: $(FILE)
	@mkdir -p $(dir $@)
	$(PYTHON) compress.py $< $@.compressed
	
	$(OBJCOPY) -I binary -O pe-x86-64 -B i386 $@.compressed $@
	
	@rm -f $@.compressed
	
	$(OBJCOPY) --rename-section .data=$(SECTION_NAME) $@
	@START_SYM=$$($(NM) $@ | grep '_start' | awk '{print $$3}') && \
	 END_SYM=$$($(NM) $@ | grep '_end' | awk '{print $$3}') && \
	 $(OBJCOPY) --redefine-sym $$START_SYM=g_packed_data $@ && \
	 $(OBJCOPY) --redefine-sym $$END_SYM=g_packed_end $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

strip:
	$(STRIP) --strip-all $(TARGET)
	@echo "Strip Success: $(TARGET)"

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BIN_DIR)/*_packed.exe