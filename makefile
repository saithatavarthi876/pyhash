DESTDIR ?= /usr/local/bin

install:
	@sudo cp pyhashh.py $(DESTDIR)/pyhashh
	@sudo chmod +x $(DESTDIR)/pyhashh
	@echo "PyHashh Installation Successful!"

uninstall:
	@sudo rm -f $(DESTDIR)/pyhashh
	@echo "PyHashh has been removed"
