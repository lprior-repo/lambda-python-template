# Lambda Python Template

This template provides a complete setup for AWS Lambda functions written in Python, using Terraform for infrastructure management.

## Structure

```
.
├── src/
│   ├── hello/          # Hello Lambda function
│   │   ├── lambda_function.py
│   │   └── requirements.txt
│   └── users/          # Users Lambda function
│       ├── lambda_function.py
│       └── requirements.txt
├── scripts/
│   └── build.py        # Build script for all functions
├── terraform/          # Terraform infrastructure
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── .github/
│   └── workflows/
│       └── build.yml   # GitHub Actions CI/CD
├── requirements.txt    # Root requirements
├── requirements-dev.txt # Development dependencies
├── Makefile
└── README.md
```

## Prerequisites

- Python 3.11+
- pip
- Terraform >= 1.0
- AWS CLI configured
- Make (optional, for using Makefile commands)

## Getting Started

1. **Clone this template**
   ```bash
   git clone <this-repo>
   cd lambda-python-template
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   # or
   make deps install-dev
   ```

3. **Build Lambda functions**
   ```bash
   python scripts/build.py
   # or
   make build
   ```

4. **Deploy infrastructure**
   ```bash
   cd terraform
   terraform init
   terraform plan
   terraform apply
   # or
   make deploy
   ```

## Development

### Adding a New Function

1. Create a new directory under `src/` (e.g., `src/orders/`)
2. Add your `lambda_function.py` and `requirements.txt` files
3. Add the function to `terraform/main.tf`
4. The build process will automatically detect and build the new function

### Building

```bash
# Build all functions
python scripts/build.py
# or
make build

# The build script will:
# - Install dependencies for each function
# - Create zip packages in the build/ directory
# - Include only production dependencies
```

### Testing

```bash
# Run tests for all functions
make test

# Run tests for a specific function
cd src/hello
python -m pytest -v
```

### Linting and Formatting

```bash
# Run all linters
make lint

# Format code
make format

# Individual tools
flake8 src/          # Style guide enforcement
black src/           # Code formatting
mypy src/            # Type checking
```

### Security

```bash
# Run security scan
make security
# or
bandit -r src/
```

## CI/CD

The GitHub Actions workflow automatically:
- Detects changed functions
- Builds each function in parallel
- Runs tests, linting, and type checking
- Performs security scans
- Creates deployment packages
- Uploads build artifacts

## Terraform Configuration

The infrastructure uses:
- **terraform-aws-modules/lambda/aws** for Lambda functions
- **terraform-aws-modules/apigateway-v2/aws** for API Gateway
- Pre-built packages (no building in Terraform)

### Customization

Edit `terraform/variables.tf` to customize:
- AWS region
- Function names
- Environment settings

## API Endpoints

After deployment, you'll get:
- `GET /hello` - Hello function
- `GET /users` - Users function

## Best Practices

### Function Structure
- Use `lambda_function.py` as the main entry point
- Follow PEP 8 style guidelines
- Include type hints for better code quality
- Use structured logging

### Dependencies
- Keep requirements.txt minimal for each function
- Use virtual environments for development
- Pin dependency versions for reproducibility

### Error Handling
- Use proper exception handling
- Log errors with context
- Return appropriate HTTP status codes

## Cost Optimization

- Functions use Python 3.11 runtime
- CloudWatch logs have 14-day retention
- API Gateway uses HTTP API (cheaper than REST API)

## Security

- IAM roles follow least privilege principle
- CloudWatch logs enabled for monitoring
- Bandit security scanning in CI/CD
- pip-audit for dependency vulnerability scanning