# ICAA Login API

A secure authentication service for the International Combat Archery Alliance (ICAA) platform, providing Google OAuth integration and user session management.

## Features

- **Google OAuth Authentication**: Secure login using Google JWT tokens
- **Session Management**: HTTP-only cookie-based authentication with JWT tokens
- **User Information**: Retrieve authenticated user details including admin status and profile information
- **OpenAPI Specification**: Full API documentation with Swagger UI
- **AWS Lambda Compatible**: Deployable as serverless functions
- **Local Development**: SAM local development environment

## API Endpoints

### Authentication
- `POST /login/google` - Authenticate with Google JWT token and receive auth cookie
- `GET /login/google/userInfo` - Get authenticated user information

### Documentation
- `/login/swagger-ui` - Swagger UI documentation (available in development)

## Quick Start

### Prerequisites

- Go 1.24+
- AWS SAM CLI (for local development)
- Docker (for containerized deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd login
   ```

2. **Build and run locally**
   ```bash
   make local
   ```
   
   The API will be available at `http://localhost:3001`

3. **Access Swagger UI**
   ```
   http://localhost:3001/login/swagger-ui
   ```

### Building

Generate OpenAPI code and build the application:
```bash
make build
```

## Configuration

### Environment Variables

- `HOST` - Server host (default: `0.0.0.0`)
- `PORT` - Server port (default: `8080`)
- `AWS_SAM_LOCAL` - Set to `true` for local development mode

### Google OAuth Setup

The service requires Google OAuth credentials to validate JWT tokens. Ensure your Google OAuth application is properly configured for your domain.

## Authentication Flow

1. Client obtains Google JWT token from Google OAuth
2. Client sends JWT to `POST /login/google`
3. Server validates JWT and returns HTTP-only cookie
4. Subsequent requests include the cookie for authentication
5. Use `GET /login/google/userInfo` to retrieve user details

## Deployment

### AWS Lambda

The service is designed to run on AWS Lambda using the AWS Lambda Web Adapter:

```bash
sam build --parameter-overrides architecture=x86_64
sam deploy
```

### Docker

Build and run the Docker container:

```bash
docker build -t icaa-login .
docker run -p 8080:8000 icaa-login
```

## Development

### Code Generation

The API uses OpenAPI code generation. After modifying `spec/api.yaml`, regenerate code:

```bash
go generate ./...
```

### Project Structure

```
├── api/           # Generated API code and handlers
├── cmd/           # Main application entry point  
├── spec/          # OpenAPI specification
├── Dockerfile     # Container configuration
├── Makefile       # Build commands
└── template.yml   # AWS SAM template
```

## Security

- JWT tokens are validated against Google's public keys
- Authentication cookies are HTTP-only and secure
- CORS protection enabled
- Input validation via OpenAPI middleware
- Structured logging for security monitoring

## License

See [LICENSE](LICENSE) file for details.
