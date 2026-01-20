.PHONY: all build clean run test fmt release setup loadtest lint

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

lint: setup
	cargo clippy --all-targets --all-features -- -D warnings

test: lint
	cargo test --workspace --exclude loadtests

fmt:
	cargo fmt

loadtest: setup
	@echo "Building bgpggd and running load tests..."
	cargo build --bin bgpggd
	cargo test -p loadtests --release -- --nocapture --test-threads=1
