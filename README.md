# Authentication Service

A Spring Boot-based authentication service implementing JWT (JSON Web Token) authentication with role-based access control.

## Features

- User registration and authentication
- JWT-based stateless authentication
- Role-based access control (RBAC)
- Password encryption using BCrypt
- RESTful API endpoints
- Exception handling with standardized error responses
- Docker support for containerization

## Technology Stack

- **Java 17+**
- **Spring Boot 3.x**
- **Spring Security**
- **JWT (JSON Web Tokens)**
- **Maven** - Build tool
- **Docker** - Containerization
- **JUnit 5** - Testing

## Project Structure

```
authentication-service/
├── src/
│   ├── main/
│   │   ├── java/com/jobseekercopilot/authenticationservice/
│   │   │   ├── config/           # Security configuration
│   │   │   ├── controller/       # REST controllers
│   │   │   ├── exception/        # Custom exceptions and handlers
│   │   │   ├── model/            # DTOs and entities
│   │   │   ├── repository/       # Data access layer
│   │   │   └── service/          # Business logic
│   │   └── resources/
│   │       └── application.properties
│   └── test/                     # Unit and integration tests
├── Dockerfile
├── pom.xml
└── README.md
```

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate user and get JWT token

### User Management

- `GET /api/users/{id}` - Get user by ID
- `GET /api/users/email/{email}` - Get user by email
- `GET /api/users/username/{username}` - Get user by username
- `GET /api/users` - Get all users

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven 3.6+
- Docker (optional, for containerization)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/mcgeeverbernard1992/authentication-service.git
   cd authentication-service
   ```

2. Build the project:
   ```bash
   mvn clean install
   ```

3. Run the application:
   ```bash
   mvn spring-boot:run
   ```

The service will start on `http://localhost:8080`

### Configuration

Configure the application in `src/main/resources/application.properties`:

```properties
# Server
server.port=8080

# Database (example with H2)
spring.datasource.url=jdbc:h2:mem:authdb
spring.datasource.driverClassName=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=password
spring.jpa.database-platform=org.hibernate.dialect.H2Dialect

# JWT
jwt.secret=your-secret-key
jwt.expiration=86400000
```

### Docker

Build and run using Docker:

```bash
# Build image
docker build -t authentication-service .

# Run container
docker run -p 8080:8080 authentication-service
```

## Usage Examples

### Register a new user

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "password123",
    "role": "USER"
  }'
```

### Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe",
    "password": "password123"
  }'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "username": "johndoe",
  "role": "USER"
}
```

### Access protected endpoint

```bash
curl -X GET http://localhost:8080/api/users/1 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Testing

Run the test suite:

```bash
mvn test
```

## Security

- Passwords are encrypted using BCrypt
- JWT tokens are used for stateless authentication
- Role-based access control implemented
- CORS configuration included
- Exception handling prevents information leakage

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License.

## Contact

For questions or support, please open an issue on GitHub.