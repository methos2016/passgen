BK_DATE=$(shell date +'%Y/%m/%d - %H:%M:%S %Z')
NAME=passgen
BIN=$(NAME)
FPC=fpc
RELEASE_UNIT=-Mobjfpc -l -B -O3 -Sih -viewnh -Fu/usr/local/include/* -XMmain -Xs -XS -XX -CX -C3- -Cg -Ci- -Co- -CO- -Cr- -Ct-
RELEASE=-Mobjfpc -l -B -O3 -OWAll -FW./bin/bm1NAKQStWvrNaqS.feedback -Sih -viewnh -Fu/usr/local/include/* -XMmain -Xs- -XS -XX -CX -C3- -Cg -Ci- -Co- -CO- -Cr- -Ct-
RELEASE2=-Mobjfpc -l -B -O3 -OwAll -Fw./bin/bm1NAKQStWvrNaqS.feedback -Sih -viewnh -Fu/usr/local/include/* -XMmain -Xs -XS -XX -CX -C3- -Cg -Ci- -Co- -CO- -Cr- -Ct-
DEBUG=-dDEBUG -Mobjfpc -l -O- -Sih -viewnh -Fu/usr/local/include/* -XMmain -Xs- -XS -XX -CX -g
SOURCE_HASH=$(shell sha256sum $(NAME).pas | grep -o '^[0-9a-fA-F]*')

release:
	@rm -rf ./bin && mkdir -p ./bin
	@export BK_DATE="$(BK_DATE)" && \
	export SOURCE_HASH="$(SOURCE_HASH)" && \
		$(FPC) $(RELEASE) ./$(NAME).pas -o./bin/$(BIN) | tr -s '\n' && \
		echo '--------------------------------------------------' && \
		$(FPC) $(RELEASE2) ./$(NAME).pas -o./bin/$(BIN) | tr -s '\n'

debug:
	@rm -rf ./bin && mkdir -p ./bin
	@export BK_DATE="$(BK_DATE)" && \
		$(FPC) $(DEBUG) ./$(NAME).pas -o./bin/$(BIN)

run:
	@./bin/$(BIN) $(ARG)

rundbg:
	@./bin/$(BIN)_dbg

install:
	chmod a+x ./bin/$(BIN)
	cp ./bin/$(BIN) /usr/local/bin

source:
	@tar -c -f $(NAME).tar *.pas *.pasinc makefile COPYING THANKS && \
	bzip2 --compress --best $(NAME).tar

clean:
	@rm -f *.o *.res *.a *.ppu ./bin/*