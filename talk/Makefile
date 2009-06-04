TARGET=oftrace.ps
#
#TEXINPUTS=.:/home/capveg/work/papers/IEEEtrans:/home/capveg/work/papers/IEEEtransBST:/usr/share/texmf/tex/latex/psnfss:/usr/share/texmf/tex/generic/misc/:/usr/share/texmf/tex/latex/base/:/usr/share/texmf/tex/latex/misc/
LATEX  = env TEXINPUTS=$(TEXINPUTS) latex
DVI    = dvips
RM     = rm
BIBTEX = bibtex
INPUTFILES = $(wildcard sections/*.tex figures/*.eps)
TGIFFIGURES=$(subst .obj,.eps,$(wildcard figures/*.obj))
SHELL  = /bin/csh
PDFTARGET=$(subst .ps,.pdf,$(TARGET))

all: $(TGIFFIGURES) $(TARGET) $(PDFTARGET)

view: all
	acroread $(PDFTARGET)
	
clean:
	$(RM) -f *~ *.snm *.nav *.toc *.aux *.log *.ps *.dvi *.pdf *.tar *.blg *.bbl *.out $(TGIFFIGURES)

# run it twice, b/c they're a buncha fuckers
%.dvi: %.tex 
	$(LATEX) $<
#	$(BIBTEX) $(subst .tex,,$<)
#	$(LATEX) $<	
	$(LATEX) $<
%.eps: %.obj
	tgif -print -eps -color $<
%.ps: %.dvi	$(INPUTFILES)
	$(DVI) -o $@ $<
%.pdf: %.dvi
	dvipdf -sPAPERSIZE=a4 $<
