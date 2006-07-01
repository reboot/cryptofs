SUBDIRS = config src doc tests

EXTRA_DIST = cryptofs.conf

noinst_DATA = README

README: doc/README.xml
	docbook2txt $<
	mv README.txt $@

