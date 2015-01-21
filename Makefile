# 
# as go generate is not present everywhere
# this makefile will provide with the necessary and missing parts.
#
## protoc --python_out=client-scripts/weechat/ -Iacpb acpb/ac.proto
## protoc --go_out=acpb\ -Iacpb ac.proto
## protoc --go_out=accp\ -Iaccp pack.proto
# XXX need to rename ac.proto   -> acpb.proto
# XXX need to rename pack.proto -> accp.proto

PROTOC=`which protoc`


acwcpb: ac.proto

ac-weechat: acwcpb


all:
	@echo "work in progress, this makefile does nothing yet
	@echo ${PROTOC}
