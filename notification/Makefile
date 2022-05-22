POSTGRESQL_URL='postgresql://postgres:postgres_password@localhost:5353/dv_notification?sslmode=disable'
POSTGRESQL_URL_TEST='postgresql://postgres:postgres_password@localhost:5353/dv_notification_test?sslmode=disable'

migrateInit:
	migrate create -ext sql -dir db/migration -seq alter_user

createDb:
	docker exec -it postgres_2 createdb -U postgres dv_notification

dropDb:
	docker exec -it postgres_2 dropdb -U postgres dv_notification --force

migrateUpTest:
	migrate -path db/migration -database ${POSTGRESQL_URL_TEST} -verbose up

migrateUpProd:
	migrate -path db/migration -database ${DB_URL} -verbose up

migrateUp:
	migrate -path db/migration -database ${POSTGRESQL_URL} -verbose up

migrateUp1:
	migrate -path db/migration -database ${POSTGRESQL_URL} -verbose up 1

migrateDown:
	migrate -path db/migration -database ${POSTGRESQL_URL} -verbose down

migrateDown1:
	migrate -path db/migration -database ${POSTGRESQL_URL} -verbose down 1

mockHandler:
	mockgen -package mock_handler -destination handler/mock/notification_handler_mock.go -source=handler/notification_handler.go

mockSvc:
	mockgen -package mock_svc -destination service/mock/notification_service_mock.go -source=service/notification_service.go

mockRepo:
	mockgen -package mock_user_repo -destination db/user/sqlc/mock/user_repository_mock.go -source=db/user/sqlc/user_repository.go

test:
	go test -v -covermode=atomic -race -coverpkg=./... ./... \
	-coverprofile coverage.out.tmp && cat coverage.out.tmp | grep -v "_mock.go" | grep -v "_gen.go" | grep -v "main.go" > coverage.out && rm coverage.out.tmp && \
	go tool cover -func coverage.out

build:
	go build -o main wire_gen.go main.go

start:
	go run wire_gen.go main.go

q2c:
	sqlc generate

checkLint:
	golangci-lint run ./... -v

fixLint:
	golangci-lint run --fix

.PHONY: migrateInit createDb migrateUp migrateUp1 migrateDown migrateDown1 q2c mockSvc mockRepo start build test checkLint fixLint
