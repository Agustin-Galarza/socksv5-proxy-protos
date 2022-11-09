COMPILE_TARGET := socks5d

SRC_DIR := ./src
BUILD_DIR := ./build
TARGET_DIR := ./bin

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)

INC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

ASAN_FLAGS := -fsanitize=address -fsanitize=undefined -fno-asynchronous-unwind-tables -fno-omit-frame-pointer
ASAN_LDFLAGS := -fsanitize=address -fsanitize=undefined

GNU_FLAGS := -D_GNU_SOURCE  -D_POSIX_C_SOURCE=200112L

CFLAGS := -std=c11 -g -Wall -Wextra -pedantic -pedantic-errors  -O3 -fno-exceptions -pthread  -Wno-unused-parameter -Wno-implicit-fallthrough 

CFLAGS += $(ASAN_FLAGS)
CFLAGS += $(GNU_FLAGS)

LDFLAGS := $(ASAN_LDFLAGS) -pthread

LDFLAGS += $(GNU_FLAGS)

all: $(TARGET_DIR)/$(COMPILE_TARGET)

$(TARGET_DIR)/$(COMPILE_TARGET): $(OBJS)
	mkdir -p ./logs
	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(OBJS) -o $@
	@chmod +x $<

$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@


clean:
	rm -fr $(BUILD_DIR)
	rm -fr $(TARGET_DIR)




.PHONY: all clean