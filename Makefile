.PHONY: all build clean run test fmt setup loadtest lint build-docker smoketest

all:
	cargo build --release

setup:
	./script/setup-protoc.sh

build:
ifndef version
	$(error version is required. Usage: make build version=v0.1.0 [platform=linux/amd64])
endif
	./script/build.sh $(version) $(platform)

build-docker: build
ifndef version
	$(error version is required. Usage: make build-docker version=v0.1.0 [platform=linux/amd64])
endif
	./docker/build.sh $(version) $(platform)

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

smoketest:
	$(MAKE) build-docker version=smoke-test platform=linux/amd64
	./smoketests/test.sh
