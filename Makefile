include config.mk

$(BUILD_DIR)/%.o: %.cc
	$(BUILD_DIR_GUARD)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR)/$(GOAL): $(OBJS)
	$(CXX)  $(CXXFLAGS) -o $@ $^

clean:
	rm -r ${BUILD_DIR}
