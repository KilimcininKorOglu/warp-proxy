.PHONY: build test vet run docker clean

build:
	go build -o bin/warp-proxy ./cmd/warp-proxy

vet:
	go vet ./...

test:
	go test -count=1 ./...

run: build
	./bin/warp-proxy -config config.yaml

docker:
	docker compose up -d --build

clean:
	rm -rf bin
