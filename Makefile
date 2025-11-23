# Makefile for rust_syslog_sniffer

INTERFACE ?= eth0
PORT ?= 514

.PHONY: all build test run clean

all: test test_e2e build

build:
	cargo build

test:
	cargo test

test_e2e:
	./tests/e2e.sh

run:
	sudo ./target/debug/syslog_sniffer --interface $(INTERFACE) --port $(PORT)

clean:
	cargo clean
