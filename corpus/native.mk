CC = clang
SOURCE_ROOT := $(abspath ../..)
BUILD_DIR ?= build
CPPFLAGS += -Isrc -I../../include
CFLAGS = -std=c17 -O2 -g -march=x86-64 -mtune=generic -fPIE -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fcf-protection=none -fno-ident -ffile-prefix-map=$(SOURCE_ROOT)=. -DNDEBUG -Wall -Wextra -Werror -pedantic
LDFLAGS = -pie -Wl,--build-id=none
SOURCES := $(sort $(wildcard src/*.c))
LIB_SOURCES := $(filter-out src/main.c,$(SOURCES))
HEADERS := $(wildcard src/*.h ../../include/*.h)
.PHONY: all test clean
all: $(BUILD_DIR)/$(PROGRAM)
$(BUILD_DIR):
	mkdir -p $@
$(BUILD_DIR)/$(PROGRAM): $(SOURCES) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) -o $@
$(BUILD_DIR)/native-test: tests/test.c $(LIB_SOURCES) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LIB_SOURCES) tests/test.c $(LDFLAGS) -o $@
test: $(BUILD_DIR)/native-test
	$(BUILD_DIR)/native-test
clean:
	rm -rf $(BUILD_DIR)
