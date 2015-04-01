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

ACBIN=$(GOPATH)/bin/ac
ACROOT=$(GOPATH)/src/github.com/unix4fun/ac
ACWSCRIPT=${ACROOT}/client-scripts/weechat/

ACW_ROOT=$(HOME)/.weechat
ACW_PYTHON=$(ACW_ROOT)/python
ACW_AUTOLOAD=$(ACW_PYTHON)/autoload


#all: ac-weechat
#	@echo "you can now use AC!"

all: gen install

clean:
	@echo "cleaning"


update:
	@echo "updating"

gen:
	@echo "generating using your protobuf"
	go generate


install: 
	@echo "go: ${GOBIN}"
	@echo "AC Weechat Root: ${ACW_ROOT}"
	@echo "AC Weechat Python: ${ACW_PYTHON}"
	@echo "AC Weechat Autoload: ${ACW_AUTOLOAD}"
	${RMBIN} ${ACW_PYTHON}/ac_pb2.py ${ACW_AUTOLOAD}/ac-weechat.py
	${LNBIN} -s ${ACROOT}/acpb/ac_pb2.py ${ACW_PYTHON}/ac_pb2.py
	${LNBIN} -s ${ACWSCRIPT}/ac-weechat.py ${ACW_AUTOLOAD}/ac-weechat.py
	@${LSBIN} -la ${ACW_AUTOLOAD}/ac-weechat.py ${ACW_PYTHON}/ac_pb2.py
