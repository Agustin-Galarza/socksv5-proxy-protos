SERVER_COMPILE_TARGET := socks5d
CLIENT_COMPILE_TARGET := socks5c

SRC_DIR := ./src
BUILD_DIR := ./build
TARGET_DIR := ./bin
TEST_DIR := ./test

# Dirs relative to src
SERVER_DIR := server
CLIENT_DIR := client
INCLUDES_DIR := includes
UTILS_DIR := utils

SV_BUILD := $(BUILD_DIR)/$(SERVER_DIR)
CL_BUILD := $(BUILD_DIR)/$(CLIENT_DIR)
UT_BUILD := $(BUILD_DIR)/$(UTILS_DIR)

SV_SRCS := $(shell find $(SRC_DIR)/$(SERVER_DIR) -name '*.c')
SV_OBJS := $(SV_SRCS:%.c=$(BUILD_DIR)/%.o)

CL_SRCS := $(shell find $(SRC_DIR)/$(CLIENT_DIR) -name '*.c')
CL_OBJS := $(CL_SRCS:%.c=$(BUILD_DIR)/%.o)

UT_SRCS := $(shell find $(SRC_DIR)/$(UTILS_DIR) -name '*.c')
UT_OBJS := $(UT_SRCS:%.c=$(BUILD_DIR)/%.o)

TEST_SRCS := $(shell find $(TEST_DIR) -name '*.c')
TEST_OBJS := $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)
TEST_COMPILE_TARGETS := $(TEST_SRCS:%.c=$(TARGET_DIR)/%)

INC_DIRS := $(shell find $(SRC_DIR)/$(INCLUDES_DIR) -type d)

########### Flags

INC_FLAGS := $(addprefix -I,$(INC_DIRS))

ASAN_FLAGS := -fsanitize=address -fsanitize=undefined -fno-asynchronous-unwind-tables -fno-omit-frame-pointer
ASAN_LDFLAGS := -fsanitize=address -fsanitize=undefined
GNU_FLAGS := -D_POSIX_C_SOURCE=200809L
LDLIBS := -pthread
# NO_UNUSED_FLAGS := -Wno-unused-variable -Wno-unused-parameter -Wno-unused-function
## Turn on optimization for production
ifdef prod
OPT_FLAGS := -O3 # optimize (remove for debugging) 
endif

CFLAGS := -std=c11 -g -Wall -Wextra -pedantic -pedantic-errors -fno-exceptions -Wno-implicit-fallthrough
CFLAGS += $(OPT_FLAGS)
CFLAGS += $(NO_UNUSED_FLAGS)
CFLAGS += $(ASAN_FLAGS)
CFLAGS += $(GNU_FLAGS)

LDFLAGS := $(ASAN_LDFLAGS) $(LDLIBS)
LDFLAGS += $(GNU_FLAGS)

SV_CFLAGS :=

SV_LDFLAGS :=

CL_CFLAGS :=

CL_LDFLAGS :=

TEST_LDFLAGS :=

########### Targets

all: server client
ifdef foo
	echo "foo is defined"
endif

server: $(TARGET_DIR)/$(SERVER_COMPILE_TARGET)

client: $(TARGET_DIR)/$(CLIENT_COMPILE_TARGET)

test: $(TEST_COMPILE_TARGETS)

$(TARGET_DIR)/$(SERVER_COMPILE_TARGET): $(SV_OBJS) $(UT_OBJS)
	@echo "socks5d target"

	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(SV_LDFLAGS) $(SV_OBJS) $(UT_OBJS) -o $@
	@chmod +x $<

$(TARGET_DIR)/$(CLIENT_COMPILE_TARGET): $(CL_OBJS) $(UT_OBJS)
	@echo "socks5c target"

	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(CL_LDFLAGS) $(CL_OBJS) $(UT_OBJS) -o $@
	@chmod +x $<

$(TEST_COMPILE_TARGETS): $(TEST_OBJS) $(UT_OBJS)
	@echo "test target"
	@echo $@
	@echo $<

	mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) $(TEST_LDFLAGS) $< $(UT_OBJS) -o $@
	@chmod +x $<

# SV_OBJS
$(BUILD_DIR)/$(SRC_DIR)/$(SERVER_DIR)/%.o: $(SRC_DIR)/$(SERVER_DIR)/%.c
	@echo "sv_objs target"
	@echo $@
	@echo $<

	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(SV_CFLAGS) $(INC_FLAGS) -c $< -o $@

# CL_OBJS
$(BUILD_DIR)/$(SRC_DIR)/$(CLIENT_DIR)/%.o: $(SRC_DIR)/$(CLIENT_DIR)/%.c
	@echo "cl_objs target"
	@echo $@
	@echo $<

	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(CL_CFLAGS) $(INC_FLAGS) -c $< -o $@

# UT_OBJS
$(BUILD_DIR)/$(SRC_DIR)/$(UTILS_DIR)/%.o: $(SRC_DIR)/$(UTILS_DIR)/%.c
	@echo "ut_objs target"
	@echo $@
	@echo $<

	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

# TEST_OBJS
$(BUILD_DIR)/$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	@echo "test_objs target"
	@echo $@
	@echo $<

	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC_FLAGS) -I./test -c $< -o $@

clean:
	rm -fr $(BUILD_DIR)
	rm -fr $(TARGET_DIR)

.PHONY: all server client clean