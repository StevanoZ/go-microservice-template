POSTGRESQL_URL='postgresql://postgres:postgres_password@localhost:5454/dv_user?sslmode=disable'
POSTGRESQL_URL_TEST='postgresql://postgres:postgres_password@localhost:5454/dv_user_test?sslmode=disable'

migrateInit:
	migrate create -ext sql -dir db/migration -seq alter_user

createDb:
	docker exec -it postgres_1 createdb -U postgres dv_user

dropDb:
	docker exec -it postgres_1 dropdb -U postgres dv_user --force

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

mockSvc:
	mockgen -package mock_svc -destination service/mock/user_service_mock.go -source=service/user_service.go

mockRepo:
	mockgen -package mock_user_repo -destination db/user/sqlc/mock/user_repository_mock.go -source=db/user/sqlc/user_repository.go -aux_files github.com/StevanoZ/dv-user/db/user/sqlc=db/user/sqlc/querier.go

test:
	go test -v -covermode=atomic -race -coverpkg=./... ./... \
	-coverprofile coverage.out.tmp && cat coverage.out.tmp | grep -v "_mock.go" | grep -v "injector.go" | grep -v "_gen.go" > coverage.out && rm coverage.out.tmp && \
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

sonarScan:
	sonar-scanner -Dproject.settings=sonar-project-local.properties

startPubSub:
	gcloud beta emulators pubsub start --project=stevanoz-dv

.PHONY: migrateInit createDb migrateUp migrateUp1 migrateDown migrateDown1 q2c mockSvc mockRepo start build test checkLint fixLint sonarScan startPubSub
