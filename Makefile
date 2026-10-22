JAR=target/cades-lt.jar
PREFIX?=$(HOME)/.local
BINDIR=$(PREFIX)/bin
SHAREDIR=$(PREFIX)/share/cades

.PHONY: all install uninstall

all: $(JAR)

$(JAR):
	mvn -q package

install: $(JAR)
	install -d $(BINDIR) $(SHAREDIR)
	install -m 755 src/main/scripts/cades $(BINDIR)/cades
	install -m 755 src/main/scripts/cades.bat $(BINDIR)/cades.bat
	install -m 644 $(JAR) $(SHAREDIR)/cades-lt.jar
	@echo "Installed to $(BINDIR)/cades (add to PATH if needed)"

uninstall:
	rm -f $(BINDIR)/cades $(BINDIR)/cades.bat
	rm -f $(SHAREDIR)/cades-lt.jar
	rmdir --ignore-fail-on-non-empty $(SHAREDIR) 2>/dev/null || true