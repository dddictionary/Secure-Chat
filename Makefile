SOURCES := $(wildcard *.c src/**/*.c *.cpp src/**/*.cpp)
OBJECTS := $(SOURCES:.c=.o)
OBJECTS := $(OBJECTS:.cpp=.o)
HEADERS := $(wildcard *.h include/*.h)

COMMON   := -O2 -Wall -Wformat=2 -Wno-format-nonliteral -march=native -DNDEBUG
CFLAGS   := $(CFLAGS) $(COMMON)
CXXFLAGS := $(CXXFLAGS) $(COMMON)
CC       := gcc
CXX      := g++
LD       := $(CXX)   # probably want $(CXX) for cpp source
LDFLAGS  := $(LDFLAGS) # -L/path/to/libs/
LDADD    := -lncurses -lreadline -lpthread -lcrypto -lgmp
INCLUDE  := # -I../path/to/headers/
DEFS     := # -DLINUX

TARGETS  := chat dh-example

IMPL := chat.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

.PHONY : all
all : $(TARGETS)

# {{{ for debugging
# DBGFLAGS := -g -UNDEBUG -Og
DBGFLAGS := -g -UNDEBUG -O0
debug : CFLAGS += $(DBGFLAGS)
# debug : CXXFLAGS += $(DBGFLAGS) -D_GLIBCXX_DEBUG
debug : CXXFLAGS += $(DBGFLAGS)
debug : all
.PHONY : debug
# }}}

chat : $(IMPL) dh.o keys.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

dh-example : dh-example.o dh.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

%.o : %.cpp $(HEADERS)
	$(CXX) $(DEFS) $(INCLUDE) $(CXXFLAGS) -c $< -o $@

%.o : %.c $(HEADERS)
	$(CC) $(DEFS) $(INCLUDE) $(CFLAGS) -c $< -o $@

.PHONY : clean
clean :
	rm -f $(TARGETS) $(OBJECTS)

# vim:ft=make:foldmethod=marker:foldmarker={{{,}}}
