# Application Instructions

## Overview

This service provides functionality to create users ("sign up") and then login to create and view notes.

### Create User

`POST /authentication/create-user`

Request body:

```json
{
  "username": "example",
  "password": "securepassword"
}
```

### Login

`POST /authentication/login`

Request body:

```json
{
  "username": "example",
  "password": "securepassword"
}
```

### Create Notes

`POST /users/:username:/notes`

Headers:

```
Bearer <token>
```

Request body:

```json
{
  "notes": "These are my notes that I want to keep secure."
}
```

### View Notes

`GET /users/:username:/notes`

Headers:

```
Bearer <token>
```

## Run the app locally

1. `cp .env.template .env.development` and modify any values as you like
2. `npm install` to install dependencies
3. `npm run dev` to start Redis and the app

An example curl request to create a user is:

```bash
curl --header "Content-Type: application/json" -i -X POST --data '{"username":"example","password":"securepassword"}' http://localhost:5000/authentication/create-user
```

## Testing

To run the unit tests:

1. The app does not need to be running.
2. `npm run test`

To run the data tests:

1. Start the app (specifically Redis) with `npm run dev`.
2. `cp .env.template .env.test` and modify any values as you like
3. `npm run test:data`

To make requests to the application:

1. Start the app with `npm run dev`.
2. Make API requests to `localhost` as documented above using curl or another tool.
