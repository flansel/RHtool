CC = gcc
CFLAGS = -W -Wall -Wextra -D_FORTIFY_SOURCE=2 -O2
LDFLAGS = -lgit2 -pthread

# Special set of build flags, for code coverage analysis
ifeq ($(COVERAGE), 1)
 CFLAGS = -W -Wall -Wextra -g -fprofile-arcs -ftest-coverage
 LDFLAGS += -lgcov
endif

# Special set of build flags, for code sanitization
# depends on libasan && libubsan
ifeq ($(SANITIZE), 1)
 CFLAGS += -fsanitize=address -fsanitize=leak -fsanitize=undefined
endif

PROGRAMS=rhel-log-parser rhel-ff-mttest
OBJECTS=asprintf.o

.PHONY: all

all: $(PROGRAMS)

$(OBJECTS): %.o: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

$(PROGRAMS): %: %.c $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) $< -o $@

clean:
	-rm -f $(PROGRAMS) $(OBJECTS) *.gc*
