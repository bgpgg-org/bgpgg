.PHONY: all build clean run test fmt release setup loadtests

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
	cargo clippy --all-targets --all-features -- -D warnings
	cargo test

fmt:
	cargo fmt

# Load tests
# Usage:
#   make loadtests                                  # Run with defaults (bgpgg, 10 senders, 10 receivers, 1000 routes)
#   make loadtests args="--senders 100 --routes 10000"  # Custom config
loadtests: setup
	./script/run-loadtests.sh $(impl) $(args)
