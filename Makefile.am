SUBDIRS = config src doc

EXTRA_DIST = cryptofs.conf

noinst_DATA = README

README: doc/README.xml
	docbook2txt $<
	mv README.txt $@

