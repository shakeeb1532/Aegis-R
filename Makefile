.PHONY: demo build build-public build-private

demo:
	./scripts/demo.sh

build:
	./scripts/build.sh

build-public:
	./scripts/build.sh public

build-private:
	./scripts/build.sh private
