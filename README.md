# Pingoo Backend

## Setup
```bash
npm install
```

## Environment Variables
Create a `.env` file:
```
MONGODB_URI=your_mongodb_atlas_connection_string
PORT=3000
```

Get free MongoDB at: https://www.mongodb.com/cloud/atlas

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
