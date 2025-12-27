.PHONY: all build clean run test fmt release setup

all: build

setup:
	./script/setup-protoc.sh

build: setup
	cargo build --release

release:
	./script/build.sh $(version)

clean:
	cargo clean

run: setup
	cargo run

test: setup
	cargo test

fmt:
	cargo fmt
