
# Wood Logs Count

Wood Logs Count is a project designed to aid post officers in efficiently counting logs. This repository contains the backend implementation of the project.

## Overview

The Wood Logs Count backend is built using Django REST Framework and utilizes Firebase Realtime Database for data storage. It offers various endpoints for authentication, user management, accessing log count functionalities, and now includes wood log counting based on uploaded images.

## Tech Stack

- Django REST Framework
- Firebase Realtime Database

## Installation

1. Clone the repository:

    ```bash
    git clone <repository_url>
    cd wood-logs-count
    ```

2. Create a virtual environment:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Create a `.env` file and add the necessary environment variables. Refer to `.env.example` for guidance.

5. Run migrations:

    ```bash
    python manage.py migrate
    ```

6. Start the development server:

    ```bash
    python manage.py runserver
    ```

## Endpoints

### Authentication

- **Signup**
  - Endpoint: `/api/v1/auth/?type=signup`
  - Method: POST
  - Description: Creates a new user account.

- **Login**
  - Endpoint: `/api/v1/auth/?type=login`
  - Method: POST
  - Description: Logs in a user and generates access and refresh tokens.

- **Logout**
  - Endpoint: `/api/v1/auth/?type=logout`
  - Method: POST
  - Description: Logs out the current user.

- **Reset Password**
  - Endpoint: `/api/v1/auth/?type=forgot_password`
  - Method: POST
  - Description: Resets the password of the logged-in user.

- **Revive Access Token**
  - Endpoint: `/api/v1/auth/?type=get_access_token`
  - Method: POST
  - Description: Generates a new access token using the refresh token.

- **Get User Profile**
  - Endpoint: `/api/v1/auth/?type=user_profile`
  - Method: GET
  - Description: Retrieves the profile details of the authenticated user.

- **Get Check Post Officers under Admin**
  - Endpoint: `/api/v1/auth/?type=get_check_post_officer_under_admin&admin_id=<admin_id>`
  - Method: GET
  - Description: Retrieves the names and IDs of the check post officers under the specified admin.

### Check Post Management

- **Register Check Post**
  - Endpoint: `/api/v1/check_post/?type=register_check_post&check_post_admin_id=<admin_id>`
  - Method: POST
  - Description: Registers a new check post under the specified admin.

- **Get Check Post List**
  - Endpoint: `/api/v1/check_post/?type=get_check_post_list&check_post_admin_id=<admin_id>`
  - Method: GET
  - Description: Retrieves all check posts under the specified admin.

- **Get Check Post List by Check Post Officer ID**
  - Endpoint: `/api/v1/check_post/?type=get_check_post_list_by_check_post_officer&check_post_officer_id=<check_post_officer_id>`
  - Method: GET
  - Description: Retrieves all check posts where the specified check post officer is registered.

### Wood Count

- **Upload Wood Log Image**
  - Endpoint: `/api/v1/woodlogs_counts/?type=upload_woodlog_image`
  - Method: POST
  - Description: Allows users to upload an image of wood logs for counting.
  - Request Body: Form Data
    - `check_post_id`: ID of the check post where the wood logs are located.
    - `check_post_officer_id`: ID of the check post officer responsible for the count.
    - `image`: Image file containing wood logs.
    - `name`: Name of the wood log image.

## Environment Variables

The following environment variables are required:

- `apiKey`: Firebase API Key
- `authDomain`: Firebase Auth Domain
- `projectId`: Firebase Project ID
- `storageBucket`: Firebase Storage Bucket
- `messagingSenderId`: Firebase Messaging Sender ID
- `appId`: Firebase App ID
- `measurementId`: Firebase Measurement ID
- `databaseURL`: Firebase Realtime Database URL
- `JWT_SECRET_KEY`: JWT Secret Key for token generation
- `JWT_ALGORITHM`: JWT Algorithm (e.g., HS256)

## Payload Examples

Here are example payloads for authentication and wood log counting endpoints:

### Signup

```json
{
    "name": "John Doe",
    "username": "johndoe",
    "email": "johndoe@example.com",
    "password": "password123",
    "role": "admin",
    "admin_id": "ABCDE12345"
}
```

### Login

```json
{
    "username": "johndoe",
    "password": "password123"
}
```

### Reset Password

```json
{
    "new_password": "new_password123",
    "old_password": "old_password123"
}
```

### Register Check Post

```json
{
    "name": "check post 1",
    "description": "Your Facility Description",
    "location": "Your Facility Location",
    "latitude": "Your Facility Latitude",
    "longitude": "Your Facility Longitude",
    "list_of_check_post_officer": ["665e512d6408246aa397c940"]
}
```

### Upload Wood Log Image

```json
{
    "check_post_id": "12345",
    "check_post_officer_id": "ABCDE67890",
    "image": "binary_data_of_image",
    "name": "wood_logs_image.jpg"
}
```
