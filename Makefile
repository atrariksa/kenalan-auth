generate:
	cd $(shell pwd)/app/internal/grpc_auth_server && protoc --go_out=. --go_opt=paths=source_relative  --go-grpc_out=. --go-grpc_opt=paths=source_relative  auth_service.proto
run:
	go run main.go

migrate:
	go run cmd\migrations\main.go cmd\migrations\migration.go sqlite3 ./cmd/migrations/test.db up

mocks:
	mockery --all --keeptree --dir=repository --output=repository/mocks --case underscore
	mockery --all --keeptree --dir=service --output=service/mocks --case underscore

test:
	go test -v -coverprofile cover.out ./...
	go tool cover -html cover.out -o cover.html 
