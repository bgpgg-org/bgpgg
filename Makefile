.PHONY: build clean run test fmt

build: fmt
	cargo build --release

clean:
	cargo clean

run:
	cargo run

test:
	cargo test

fmt:
	cargo fmt
