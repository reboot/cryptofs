SUBDIRS = config src doc tests

EXTRA_DIST = cryptofs.conf

noinst_DATA = README

README: doc/README.xml
	docbook2txt $<
	sed -e 's#{download}#Downloads are available from http://reboot.animeirc.de/cryptofs/#' < $@.txt > $@
	rm $@.txt

release: distcheck
	gzip --stdout --decompress $(distdir).tar.gz | bzip2 --compress > $(distdir).tar.bz2

# configure with CFLAGS="-fprofile-arcs -ftest-coverage"
# needs libtool patch for lcov
coverage: clean zerocounters check
	lcov --directory src/ --capture --output-file cryptofs.info 
	genhtml --frames --prefix `pwd`/src --output-directory coverage cryptofs.info 

zerocounters:
	lcov --directory src/ --zerocounters
