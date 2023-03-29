.PHONY: proto
.DEFAULT_GOAL := default

PROTO_FILES := targetcert.proto

PROTOC_GEN_GOFAST := $(shell command -v protoc-gen-gofast 2> /dev/null)
PROTOC_GEN_GOFASTER := $(shell command -v protoc-gen-gogofaster 2> /dev/null)

deps:
	go install github.com/gogo/protobuf/protoc-gen-gofast@v1.3.2

proto: deps
	protoc -I=./ -I${GOPATH}/src/ --gofast_out=plugins=grpc,Mgithub.com/procyonai/targetcert/controller/model/common.proto=github.com/procyonai/targetcert/controller/model:../golang/generated/ $(PROTO_FILES)
	gofmt -s -w ../golang/generated/

default: proto
