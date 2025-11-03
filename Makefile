.PHONY: build clean run test fmt release setup

setup:
	command -v protoc >/dev/null 2>&1 || sudo apt-get update && sudo apt-get install -y protobuf-compiler

build: fmt
	cargo build --release

release:
	./script/build.sh $(version)

clean:
	cargo clean

run:
	cargo run

test:
	cargo test

fmt:
	cargo fmt
