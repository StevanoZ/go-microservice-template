# Golang Microservices (CI/CD)
The technologies used are Golang, PostgreSql, Kafka, Redis, GCP. This app is now live on www.stevanoz.xyz (will be closed if the billing runs out).
For architecture I used clean architecture (best practice for testability). And sharing dependencies within apps (use public Go lib [share Go lib](https://github.com/StevanoZ/dv-shared)).

This application has 2 services:
* **User**. For API spec you can visit this url https://stevanoz.xyz/api/user/doc/
* **Notification**. For API spec you can visit this url https://stevanoz.xyz/api/notification/doc/


## How To Run This App
Make sure you already installed this tools on your local machine:
* **Kubectl**. https://kubernetes.io/docs/tasks/tools
* **Skaffold**. For live reloading while developing app. https://skaffold.dev/docs/install
* **Google Cloud CLI**. For access, and manage k8s cluster. https://cloud.google.com/sdk/docs/install
* **Postgres, Redis, Kafka**
* **Ingress-Nginx**. For routing purpose (You can install with or without helm). https://kubernetes.github.io/ingress-nginx/deploy/#quick-start
* **Fill environment variables**. Copy paste **test.env** and rename it to **app.env** in same folder (app). And replace the environment variables with your own environment variables. eg: DB_SOURCE replace with postgres url on your local machine.
* **Add fake host for local machine**. eg: If you using VS Code, on your terminal type **code /etc/hosts** and add this before the end of section (bottom line) **127.0.0.1 stevanoz.dev.xyz**. This is the default set up, but you can change it for whatever domain you want such **127.0.0.1 your-tesing-domain.com**. If you change it, you also need to change ingress config in **infras/k8s-dev/ingress-svc.yaml** and replace **host: stevanoz.dev.xyz** to **host: your-tesing-domain.com**.
* **Run Migration Scripts**. Only need for first time, when you clone or copy this project. eg: In your PostgreSql create 2 databases **(dv_user && dv_notification)** and run all migration script in user and notification folder -> **migrate -path db/migration -database ${YOUR_POSTGRESQL_URL} -verbose up**.

If everything is installed and you already fill environment variables and also ingress-nginx setup. In root folder just type **skaffold dev** and the application will run.

**Summary total code coverage (update automatically)**:
* **User**. ![cod cov](http://dv-bucketz.storage.googleapis.com/dv-user/codcov.svg)
* **Notification**. ![cod cov](http://dv-bucketz.storage.googleapis.com/dv-notification/codcov.svg)

**Threshold for total code coverage is 90%. <br />**
Example for success (>= 90%):
<img width="959" alt="Succes Coverage" src="https://user-images.githubusercontent.com/51188834/169705410-7d99a827-e814-462a-9954-37d88313f0aa.png">

Example for failed (< 90%). For this example I have set the threshold to 97%. That's why the test failed:
<img width="959" alt="Failed Coverage" src="https://user-images.githubusercontent.com/51188834/169705481-6c2b5489-5ee4-44e1-a4a5-ee7c71481433.png">


## Tech Related

**Clean Architecture**. <br />
**Sqlc**. Relatively faster than ORM. As fast as database/sql. <br />
**Chi**. Fast, lightweight, idiomatic. 100% compatible with net/http so you can easily modify it as you want. <br />
**Google Wire**. Automatically generate Dependency Injection. <br />
**Golang Migrate**. For database migration. <br />
