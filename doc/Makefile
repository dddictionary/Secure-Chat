SHELL = bash
main = readme
css = ""
extras := "-H csshead -H ../../../html/light.css -H cssfoot"
gmakefile := "../../pandoc_makefile"
pubdocs := $(wildcard ../*-skel.cpp ../*.h) \
	../Makefile \
	../dh.c \
	../dh-example.c \
	../.gitignore \
	../params \
	../openssl-examples/ \
	readme.html
pubdir := /home/wes/repos/ccny/teaching/codearchives/csc380-projects/p1/
gradingdocs := $(wildcard ../*.c ../*.h) ../Makefile
gradingdir := /tmp/430grading

$(main).html: %.html: $(main).mkd csshead cssfoot
	make -f $(gmakefile) main=$(main) css=$(css) moreargs=$(extras)

csshead :
	echo '<style type="text/css">' >> csshead

cssfoot :
	echo "</style>" > cssfoot

.PHONY : pub
pub : $(pubdocs)
	mkdir -p $(pubdir)
	cp -r $(pubdocs) $(pubdir)
	for f in $(pubdir)/*-skel.cpp ; do mv $$f $${f/-skel.cpp/.cpp} ; done

grading : $(gradingdocs)
	mkdir -p $(gradingdir)
	cp $(gradingdocs) $(gradingdir)

.PHONY : clean
clean :
	rm -f csshead cssfoot readme.html
