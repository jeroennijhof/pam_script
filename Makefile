CC=gcc
CFLAGS=-fPIC
LDFLAGS=-fPIC -shared -lpam
OBJECT=pam_script.o
EXEC=pam_script.so.1

all: $(EXEC)

$(EXEC): $(OBJECT)
	$(CC) $(LDFLAGS) $(OBJECT) -o $@

install:
	cp $(EXEC) /lib/security/
	ln -f -s $(EXEC) /lib/security/pam_script.so

clean:
	rm -f $(OBJECT)
	rm -f $(EXEC)
