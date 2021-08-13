CXX = g++

BUILD_DIR = build
INCLUDE_DIR = include

CXXFLAGS = -std=c++17 -Wall -fmax-errors=2 -lpthread \
		   -I${INCLUDE_DIR} -O2 -flto

build_dir_guard = @mkdir -p $(BUILD_DIR)

pdping: pdping.cc
	$(build_dir_guard)
	$(CXX) pdping.cc $(CXXFLAGS) -o $(BUILD_DIR)/$@ 

clean:
	rm -r ${BUILD_DIR}
