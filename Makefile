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
LNBIN=/bin/ln
LSBIN=/bin/ls
RMBIN=/bin/rm
MKDIR=/bin/mkdir

ACBIN=$(GOPATH)/bin/ac
ACROOT=$(GOPATH)/src/github.com/unix4fun/ac
ACWSCRIPT=${ACROOT}/client-scripts/weechat

ACW_ROOT=$(HOME)/.weechat
ACW_PYTHON=$(ACW_ROOT)/python
ACW_AUTOLOAD=$(ACW_PYTHON)/autoload

AC_HOME=$(HOME)/.ac

CURRENT=$(shell date +%Y%m%d)


#PROTOC=`which protoc`
#ACROOT=/Users/eau/dev/go/src/github.com/unix4fun/ac
#ACROOT=.
#ACPB=${ACROOT}/acpb
#ACCP=${ACROOT}/accp
#ACWEECHAT=${ACROOT}/client-scripts/weechat

#ifneq ("/Users/eau/tools/go/bin/go", "")
#else
#endif


all: update
	@echo "you can test/use AC && commit!"

clean:
	@echo "cleaning"
	rm -rf ac ac.debug.txt

update: version
	@echo "updating proto & version"
	@go generate

# might not work on windows while it should
# XXX TODO: windows support
version:
	@echo "Generating ${CURRENT}"
	@echo "package main\nconst acVersion string = \"`date +%Y%m%d`\"\n" > version.go
	@sed s/SCRIPT_VERSION\ =\ '.*'/SCRIPT_VERSION\ =\ \'${CURRENT}\'/g  ${ACWSCRIPT}/ac-weechat.py > ${ACWSCRIPT}/ac-weechat.py.${CURRENT}
	@diff -sru ${ACWSCRIPT}/ac-weechat.py ${ACWSCRIPT}/ac-weechat.py.${CURRENT} || if [ $$? -eq 1 ]; then echo "Ok/Ctrl+C" && read t; else exit 0; fi
	#|| [ $$? -eq 1 ]; then echo "$(?) Ok/Ctrl+C?" && read t
#	@echo "OK Ctrl-C to stop"
#	@read t
	@cat ${ACWSCRIPT}/ac-weechat.py.${CURRENT} > ${ACWSCRIPT}/ac-weechat.py
	@rm -i ${ACWSCRIPT}/ac-weechat.py.${CURRENT}

#ac:
#	@echo "generate AC Go Protobuf"
#	${PROTOC} --go_out=${ACPB} -Iacpb ${ACPB}/ac.proto
#	${PROTOC} --go_out=${ACCP} -Iaccp ${ACCP}/ac.proto
# XXX TODO:
# - test GOBIN existence
# - test ACW_ROOT and _PYTHON existence

install: 
	@echo "go: ${GOBIN}"
	@echo "AC Weechat Root: ${ACW_ROOT}"
	@echo "AC Weechat Python: ${ACW_PYTHON}"
	@echo "AC Weechat Autoload: ${ACW_AUTOLOAD}"
	@echo "AC Home: ${AC_HOME}"
	${MKDIR} -p ${AC_HOME}
	${RMBIN} -f ${ACW_PYTHON}/ac_pb2.py ${ACW_AUTOLOAD}/ac-weechat.py
	${LNBIN} -s ${ACWSCRIPT}/ac_pb2.py ${ACW_PYTHON}/ac_pb2.py
	${LNBIN} -s ${ACWSCRIPT}/ac-weechat.py ${ACW_AUTOLOAD}/ac-weechat.py
	@${LSBIN} -la ${ACW_AUTOLOAD}/ac-weechat.py ${ACW_PYTHON}/ac_pb2.py
