# Makefile for rust_syslog_sniffer

INTERFACE ?= eth0
PORT ?= 514

.PHONY: all build test run clean

all: test build

build:
	cargo build

test:
	cargo test

run:
	sudo ./target/debug/syslog_sniffer --interface $(INTERFACE) --port $(PORT)

clean:
	cargo clean
