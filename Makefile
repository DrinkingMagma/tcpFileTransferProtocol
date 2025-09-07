CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
INCLUDES = 
LIBS = -lssl -lcrypto -lpthread  -lstdc++fs

SRCDIR = .
SOURCES = tcp_server.cpp tcp_client.cpp main.cpp file_transfer_protocol.cpp
OBJECTS = $(SOURCES:.cpp=.o)
TARGET = tcp_file_transfer

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean