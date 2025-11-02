.PHONY: build clean run test

build:
	cargo build --release

clean:
	cargo clean

run:
	cargo run

test:
	cargo test
