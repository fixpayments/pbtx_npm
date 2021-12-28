all: lib/pbtx_pb.js

lib/pbtx_pb.js: ../pbtx/pbtx.proto
	protoc -I../pbtx pbtx.proto --js_out=import_style=commonjs,binary:lib

clean:
	rm -rf lib/pbtx_pb.js node_modules/
