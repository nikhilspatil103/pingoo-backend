# Koozi Backend

## Setup
```bash
npm install
```

## Run
```bash
npm run dev
```

## API Endpoints

### POST /api/signup
Create a new user account

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "message": "User created successfully",
  "userId": 1
}
```
