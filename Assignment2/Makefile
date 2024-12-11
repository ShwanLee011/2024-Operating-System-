# indicating that target "all" and "clean" are not files
.PHONY: all clean

# set some variables
CC = gcc
CFLAGS = -Wall -Wextra -Werror -O3 -Wpedantic
OUTPUT_OPTION = -MMD -MP -o $@
SOURCE = sched_demo_312512011.c
OBJS = $(SOURCE:.c=.o)
DEPS = $(SOURCE:.c=.d) 
TARGET = sched_demo_312512011

# first command of make
all: $(TARGET)

# import the dependencies of .h .c files from the compiler
-include $(DEPS)

# implicit targets for generating .o files
#%.o: %.c
#	$(CC) -c $(CFLAGS) -o $@ $<

# linking the object files to generate the executable
$(TARGET): $(OBJS)
	$(CC) $^ -o $@

# cleaning up generated files
clean:
	@rm -f $(TARGET) $(OBJS) $(DEPS)
