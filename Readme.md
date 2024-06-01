The Authentication in Golang, contains a simple way to make an account and login, forget password, reset password, generate authentication token, and protected routes. It uses Gin as the web framework and Gorm as the ORM. The database used is Postgres.


## Features
- **Account** \
Just a Simple Account Creation and Login API


## Prerequisites
Before you begin, ensure you have the following installed:
Go
Gin
Gorm
Postgres / ElephantSQL

## Installation
To install the project, run the following:
git clone
cd into the project directory
go get ./...
go mod tidy


## Usage
To start the server, run the following
go run main.go


## API Endpoints
- **POST /account** 
Creates a new account. 
Request Body: 
`{ "email": "", "password": "password" }` 
Response: 
`{ "id": 1, "email": "email" }`
 
##
- **POST /login** 
Logs in a user. 
Request Body: 
`{ "email": "email", "password": "password" }` 
Response: 
`{ "id": 1, "email": "email" }`


Contributing
Contributions to this project are welcome. Please fork the repository and submit a pull request.
