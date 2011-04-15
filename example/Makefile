PROJECT = trapd
CFLAGS = -g
LDFLAGS = -lnetsnmp

all: $(PROJECT)

$(PROJECT): $(PROJECT).o
	$(LINK.c) $(OUTPUT_OPTION) $<

clean:
	rm -rf *.o $(PROJECT)
