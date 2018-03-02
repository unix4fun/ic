# 
# as go generate is not present everywhere
# this makefile will provide with the necessary and missing parts.
#
## protoc --python_out=client-scripts/weechat/ -Iacpb acpb/ac.proto
## protoc --go_out=acpb/ -Iacpb ac.proto
## protoc --go_out=accp/ -Iaccp pack.proto
# XXX need to rename ac.proto   -> acpb.proto
# XXX need to rename pack.proto -> accp.proto
# 
#

GOBIN=$(shell which go)
LNBIN=$(shell which ln)
LSBIN=$(shell which ls)
RMBIN=$(shell which rm)
MKDIR=$(shell which mkdir)

ACBIN=$(GOPATH)/bin/ic
ACROOT=$(GOPATH)/src/github.com/unix4fun/ic
ACWSCRIPT=${ACROOT}/client-scripts/weechat

ACW_ROOT=$(HOME)/.weechat
ACW_PYTHON=$(ACW_ROOT)/python
ACW_AUTOLOAD=$(ACW_PYTHON)/autoload

AC_HOME=$(HOME)/.ic

CURRENT=$(shell date +%Y%m%d)

all: update install
	@echo go: ${GOBIN}
	@echo "you can test/use IC && commit!"

clean:
	@echo "cleaning"
	rm -rf ic ic.debug.txt

ver-update: version
	@echo "updating proto & version"
	@go generate

# might not work on windows while it should
# XXX TODO: windows support
version:
	@echo "Generating ${CURRENT}"
	@echo "package main\nconst icVersion string = \"`date +%Y%m%d`\"\n" > version.go
	@sed s/SCRIPT_VERSION\ =\ '.*'/SCRIPT_VERSION\ =\ \'${CURRENT}\'/g  ${ACWSCRIPT}/ic-weechat.py > ${ACWSCRIPT}/ic-weechat.py.${CURRENT}
	@diff -sru ${ACWSCRIPT}/ic-weechat.py ${ACWSCRIPT}/ic-weechat.py.${CURRENT} || if [ $$? -eq 1 ]; then echo "Ok/Ctrl+C" && read t; else exit 0; fi
	#|| [ $$? -eq 1 ]; then echo "$(?) Ok/Ctrl+C?" && read t
#	@echo "OK Ctrl-C to stop"
#	@read t
	@cat ${ACWSCRIPT}/ic-weechat.py.${CURRENT} > ${ACWSCRIPT}/ic-weechat.py
	@rm -i ${ACWSCRIPT}/ic-weechat.py.${CURRENT}

# XXX TODO:
# - test GOBIN existence
# - test ACW_ROOT and _PYTHON existence
#
update:
	@${GOBIN} get -u github.com/unix4fun/ic

install: 
	@echo "go: ${GOBIN}"
	@echo "AC Weechat Root: ${ACW_ROOT}"
	@echo "AC Weechat Python: ${ACW_PYTHON}"
	@echo "AC Weechat Autoload: ${ACW_AUTOLOAD}"
	@echo "AC Home: ${AC_HOME}"
	${MKDIR} -p ${AC_HOME}
	${RMBIN} -f ${ACW_AUTOLOAD}/ic-weechat.py
	${LNBIN} -s ${ACWSCRIPT}/ic-weechat.py ${ACW_AUTOLOAD}/ic-weechat.py
	@${LSBIN} -la ${ACW_AUTOLOAD}/ic-weechat.py
	@${LSBIN} -la ${ACBIN}
