CXX = g++

BUILD_DIR = build

ifeq (${DEBUG}, gdb)
MODE = -ggdb
endif
ifeq (${DEBUG}, lldb)
MODE = -g
endif
ifndef DEBUG
MODE = -o2 -flto
endif

CXXFLAGS = -std=c++17 -Wall ${MODE}

BUILD_DIR_GUARD = @mkdir -p $(BUILD_DIR)

GOAL = main

FILES = main 
OBJS = $(FILES:%=$(BUILD_DIR)/%.o)
