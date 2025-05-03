# Auth Service Assignment

## How to Run

docker build -t acharya-auth-api .

docker run -p 8080:8080 acharya-auth-api


## Test Commands 

1) SignUp

curl -X POST http://localhost:8080/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "hari@email.com", "password": "password3008"}'

2) SignIn [with JWT as response]

curl -X POST http://localhost:8080/signin \
  -H "Content-Type: application/json" \
  -d '{"email": "hari@email.com", "password": "password3008"}'

3) Refresh Token [replace refresh-token with token from the signIN API response]

curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "refresh-token"}'

4) Revoke Token [replce your-access-token with token from the signIn API response]

curl -X POST http://localhost:8080/revoke \
  -H "Content-Type: application/json" \
  -d '{"token": "your-access-token"}'

5) Authorization [Ensure you don't run the revoke token command before testing this]

curl -X GET http://localhost:8080/protected \
  -H "Authorization: Bearer your-access-token"