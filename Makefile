TOP_DIR=.
OUTPUT_DIR=$(TOP_DIR)/output
README=$(TOP_DIR)/README.md

BUILD_NAME=abt_did_elixir
VERSION=$(strip $(shell cat version))
ELIXIR_VERSION=$(strip $(shell cat .elixir_version))
OTP_VERSION=$(strip $(shell cat .otp_version))

build:
	@echo "Building the software..."
	@rm -rf _build/dev/lib/abt_did_elixir
	@make format

format:
	@mix compile; mix format;

init: submodule install dep
	@echo "Initializing the repo..."

travis-init: submodule extract-deps
	@echo "Initialize software required for travis (normally ubuntu software)"

install:
	@echo "Install software required for this repo..."
	@mix local.hex --force
	@mix local.rebar --force

dep:
	@echo "Install dependencies required for this repo..."
	@mix deps.get

pre-build: install dep
	@echo "Running scripts before the build..."

post-build:
	@echo "Running scripts after the build is done..."

all: pre-build build post-build

test:
	@echo "Running test suites..."
	@MIX_ENV=test mix test --no-start

doc:
	@echo "Building the documentation..."

precommit: pre-build build post-build test

travis: precommit

travis-deploy:
	@echo "Deploy the software by travis"
	@make build-release
	@make release

clean: clean-api-docs
	@echo "Cleaning the build..."

watch:
	@make build
	@echo "Watching templates and slides changes..."
	@fswatch -o src/ | xargs -n1 -I{} make build

run:
	@echo "Running the software..."
	@iex -S mix

submodule:
	@git submodule update --init --recursive

rebuild-deps:
	@rm -rf mix.lock; rm -rf deps/utility_belt;
	@make dep

include .makefiles/*.mk

.PHONY: build init travis-init install dep pre-build post-build all test doc precommit travis clean watch run bump-version create-pr submodule build-release
