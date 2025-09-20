# Enhanced AWS Lambda Python Template 🚀⚡

[![CI/CD Pipeline](https://github.com/your-org/lambda-python-template/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/lambda-python-template/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/your-org/lambda-python-template/branch/main/graph/badge.svg)](https://codecov.io/gh/your-org/lambda-python-template)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade AWS Lambda Python service template implementing advanced serverless patterns from the [aws-lambda-handler-cookbook](https://github.com/ran-isenberg/aws-lambda-handler-cookbook). This template provides a complete, production-ready foundation for building scalable, maintainable, and highly observable serverless applications with **zero CloudFormation** - using only serverless.tf modules.

## 🌟 What's New in This Enhanced Version

### 🎯 **Core Business Logic & APIs**
- ✅ **Complete Order Management API** with real business logic
- ✅ **Advanced Error Handling** with custom exception hierarchy
- ✅ **Lambda Powertools Idempotency** for reliable operations
- ✅ **Enhanced Data Access Layer** with comprehensive DynamoDB patterns
- ✅ **API Gateway REST API** with validation and CORS

### 🏗️ **Event-Driven Architecture Patterns**
- ✅ **Event Sourcing** with DynamoDB event store and snapshots
- ✅ **CQRS Patterns** with read model projections and command/query separation
- ✅ **EventBridge Integration** with schema validation and dead letter queues
- ✅ **Saga Patterns** for distributed transaction coordination
- ✅ **Event Handler Decorators** with routing and error handling

### 🔒 **Enterprise Security Features**
- ✅ **JWT Authentication** with JWKS support and token validation
- ✅ **API Key Authentication** with DynamoDB backend and caching
- ✅ **Rate Limiting** with multiple algorithms (token bucket, sliding window)
- ✅ **Input Validation & Sanitization** with XSS/SQL injection protection
- ✅ **Security Headers** middleware with CSP and OWASP compliance

### 📊 **Advanced Observability & Configuration**
- ✅ **AWS AppConfig Integration** for feature flags and dynamic configuration
- ✅ **Comprehensive Health Monitoring** with detailed system checks
- ✅ **Enhanced Security** with WAF integration and security scanning
- ✅ **Advanced Observability** with custom metrics and dashboards
- ✅ **Performance Monitoring** with benchmarking and profiling tools

## 🎯 Enterprise Features

### 🏗️ **Advanced Three-Layer Architecture**
- **Handlers Layer**: Enhanced API Gateway integration with comprehensive request validation
- **Logic Layer**: Sophisticated business logic with feature flags, idempotency, and event publishing
- **Data Access Layer**: Enterprise-grade DynamoDB patterns with error handling and retry logic

### 🔧 **Modern Python Development Stack**
- **UV Package Manager**: Lightning-fast dependency management (3-10x faster than pip)
- **Ruff**: Ultra-fast linting and formatting (10-100x faster than legacy tools)
- **mypy**: Comprehensive type checking with strict mode
- **Pydantic v2**: High-performance data validation and serialization
- **pytest**: Advanced testing with parametrization, fixtures, and markers

### 📊 **Production-Grade Observability**
- **AWS Lambda Powertools**: Full observability suite with correlation IDs
- **Structured Logging**: JSON logging with contextual information
- **Distributed Tracing**: X-Ray integration with custom annotations
- **Custom Metrics**: Business KPIs, performance metrics, and error tracking
- **Health Monitoring**: Multi-layer health checks with detailed diagnostics

### 🔒 **Enterprise Security & Reliability**
- **Input Validation**: Multi-layer validation with Pydantic and API Gateway
- **Idempotency**: Reliable operations with DynamoDB-backed deduplication
- **Error Handling**: Comprehensive error hierarchy with user-friendly messages
- **Feature Flags**: Dynamic configuration and gradual feature rollouts
- **Security Scanning**: Automated vulnerability detection and dependency scanning
- **WAF Integration**: Optional Web Application Firewall protection

### 🧪 **Comprehensive Testing Strategy**
- **Unit Tests**: Fast, isolated component testing with mocking
- **Integration Tests**: Real DynamoDB integration with LocalStack/moto
- **E2E Tests**: Complete API testing with realistic scenarios
- **Contract Tests**: API contract validation and schema testing
- **Performance Tests**: Load testing and benchmark monitoring
- **Security Tests**: Automated security vulnerability scanning

### 🚀 **Advanced CI/CD Pipeline**
- **Change Detection**: Smart deployment based on code changes
- **Quality Gates**: Comprehensive pre-deployment validation
- **Parallel Execution**: Fast pipeline with concurrent job execution
- **Security Integration**: SAST, DAST, and dependency scanning
- **Cost Analysis**: Infrastructure cost estimation and optimization
- **Deployment Strategies**: Blue-green deployments with automatic rollback

### 💡 **Real-World Implementation**
- **Complete Order Management System**: Full CRUD operations with business logic
- **Event-Driven Architecture**: EventBridge integration for scalable event processing
- **Dynamic Configuration**: AWS AppConfig for runtime configuration management
- **API Documentation**: Comprehensive OpenAPI 3.0 specification
- **Monitoring Dashboards**: CloudWatch dashboards and alerting
- **Performance Optimization**: Cold start optimization and memory tuning

## 🚀 Quick Start

### Prerequisites

- Python 3.13+
- [Task](https://taskfile.dev/) (task runner)
- [UV](https://github.com/astral-sh/uv) (Python package manager)
- [Terraform](https://www.terraform.io/) 1.13+
- AWS CLI configured

### 1. Bootstrap Your Development Environment

```bash
# Clone the template
git clone <your-repo-url>
cd lambda-python-template

# Setup development environment with UV
task dev

# This will:
# - Install UV if not present
# - Create virtual environment
# - Install all dependencies
# - Setup pre-commit hooks
# - Initialize Terraform
```

### 2. Run Tests

```bash
# Run all tests
task test

# Run specific test types
task test:unit          # Unit tests only
task test:integration   # Integration tests with DynamoDB
task test:e2e          # End-to-end API tests
task test:benchmark    # Performance benchmarks
```

### 3. Code Quality Checks

```bash
# Run all quality checks
task lint

# Individual checks
task format:check      # Code formatting
task type:check       # Type checking with mypy
task security:scan    # Security vulnerability scanning
task complexity:check # Code complexity analysis
```

### 4. Deploy to AWS

```bash
# Deploy to development
task deploy:dev

# Deploy to staging
task deploy:staging

# Deploy to production (requires approval)
task deploy:prod
```

## 📁 Project Structure

```
├── src/service/                    # Main service code
│   ├── handlers/                   # 🎯 API handlers & entry points
│   │   ├── models/                 # Handler-specific models
│   │   ├── utils/                  # Handler utilities
│   │   │   ├── observability.py   # Centralized logging/tracing/metrics
│   │   │   ├── rest_api_resolver.py # API Gateway integration
│   │   │   └── dynamic_configuration.py # Feature flags & config
│   │   └── handle_*.py            # Individual handler functions
│   ├── logic/                      # 🧠 Business logic layer
│   │   ├── utils/                  # Logic utilities (idempotency, etc.)
│   │   └── *.py                   # Business operations
│   ├── dal/                        # 💾 Data access layer
│   │   ├── __init__.py            # DAL interfaces
│   │   └── db_handler.py          # DynamoDB implementation
│   ├── events/                     # 🚀 Event sourcing & CQRS patterns
│   │   ├── __init__.py            # Event exports
│   │   ├── event_schemas.py       # Pydantic event schemas & validation
│   │   ├── event_publisher.py     # EventBridge publisher with batching
│   │   ├── event_handler.py       # Event handler decorators & routing
│   │   └── event_sourcing.py      # Event store, projections & snapshots
│   ├── security/                   # 🔒 Security patterns & middleware
│   │   ├── __init__.py            # Security exports
│   │   ├── auth.py                # JWT/API key authentication
│   │   ├── rate_limiter.py        # Rate limiting with multiple algorithms
│   │   ├── input_validator.py     # Input sanitization & validation
│   │   ├── security_headers.py    # Security headers middleware
│   │   └── secrets_manager.py     # AWS Secrets Manager integration
│   └── models/                     # 📋 Data models & schemas
│       ├── input.py               # Request validation models
│       ├── output.py              # Response models
│       └── order.py               # Domain models
├── tests/                          # 🧪 Test suite
│   ├── unit/                      # Unit tests
│   ├── integration/               # Integration tests
│   ├── e2e/                       # End-to-end tests
│   ├── benchmark/                 # Performance tests
│   └── conftest.py               # Shared test fixtures
├── terraform/                      # 🏗️ Infrastructure as Code
├── scripts/                        # 🔧 Utility scripts
├── .github/workflows/             # 🚀 CI/CD pipelines
├── Taskfile.yml                   # 📋 Development tasks
├── pyproject.toml                 # 📦 Python project configuration
├── requirements.txt               # Production dependencies
├── requirements-dev.txt           # Development dependencies
└── openapi.yaml                   # 📚 API documentation
```

## 📚 API Documentation

The service automatically generates OpenAPI 3.0 documentation from your Pydantic models and handler decorators.

### Generate Documentation

```bash
# Generate OpenAPI spec
task docs:generate

# Validate OpenAPI spec
task openapi:validate

# Serve documentation locally
task docs:serve
```

### Available Endpoints

- `POST /api/orders` - Create a new order
- `GET /api/orders/{id}` - Retrieve an order by ID
- `PUT /api/orders/{id}` - Update an existing order
- `DELETE /api/orders/{id}` - Delete an order
- `GET /health` - Service health check
- `GET /swagger` - Interactive API documentation

## 🔧 Configuration

### Environment Variables

The service uses type-safe environment variable handling with `aws-lambda-env-modeler`:

```python
from service.handlers.models.env_vars import get_handler_env_vars

env_vars = get_handler_env_vars()
table_name = env_vars.TABLE_NAME
debug_mode = env_vars.is_development
```

### Feature Flags

Dynamic configuration is managed through AWS AppConfig:

```python
from service.handlers.utils.dynamic_configuration import get_feature_flag

# Simple feature flag
campaign_enabled = get_feature_flag("ten_percent_campaign", default=False)

# Context-aware feature flag
premium_features = get_feature_flag(
    "premium_user_features",
    context={"customer_email": "user@example.com"},
    default=False
)
```

## 🧪 Testing Strategy

### Test Types

1. **Unit Tests** (`tests/unit/`): Fast, isolated tests for individual components
2. **Integration Tests** (`tests/integration/`): Test interactions between components
3. **E2E Tests** (`tests/e2e/`): Full API testing with real HTTP requests
4. **Benchmark Tests** (`tests/benchmark/`): Performance regression testing

### Running Tests

```bash
# All tests with coverage
task test

# Test with coverage report
task coverage:report

# Watch mode for TDD
task test:watch

# Run tests with specific markers
pytest -m "unit"           # Only unit tests
pytest -m "integration"    # Only integration tests
pytest -m "not slow"       # Skip slow tests
```

### Test Fixtures

The template includes comprehensive fixtures in `tests/conftest.py`:

- DynamoDB table setup with moto
- Sample data generation
- API Gateway event simulation
- Lambda context mocking
- Performance timing utilities

## 🚀 Deployment

### Infrastructure

The template uses Terraform for infrastructure management with:

- DynamoDB table with proper indexing
- Lambda function with optimized configuration
- API Gateway with CORS and validation
- CloudWatch dashboards and alarms
- IAM roles with least privilege

### Deployment Environments

```bash
# Development (automatic on develop branch)
task deploy:dev

# Staging (manual approval required)
task deploy:staging

# Production (manual approval + additional gates)
task deploy:prod
```

### CI/CD Pipeline

The GitHub Actions workflow includes:

1. **Quality Gates**: Linting, type checking, security scanning
2. **Testing**: Unit, integration, and E2E tests
3. **Build**: Lambda package creation with UV
4. **Security**: Dependency scanning and infrastructure security
5. **Deploy**: Automatic deployment to development
6. **Monitoring**: Performance and cost tracking

## 📊 Observability

### Logging

Structured logging with correlation IDs:

```python
from service.handlers.utils.observability import logger

logger.info("Processing order", extra={
    "order_id": order.id,
    "customer_email": order.customer_email,
    "item_count": order.item_count
})
```

### Tracing

Distributed tracing with AWS X-Ray:

```python
from service.handlers.utils.observability import tracer

@tracer.capture_method
def process_order(order_data):
    tracer.put_annotation("order_type", "premium")
    tracer.put_metadata("order_details", order_data)
    # ... business logic
```

### Metrics

Custom business metrics:

```python
from service.handlers.utils.observability import metrics
from aws_lambda_powertools.metrics import MetricUnit

metrics.add_metric(name="OrdersCreated", unit=MetricUnit.Count, value=1)
metrics.add_metric(name="OrderValue", unit=MetricUnit.None, value=order.total)
```

### Monitoring

- **CloudWatch Dashboards**: High-level and detailed views
- **CloudWatch Alarms**: Error rate, latency, and business metrics
- **X-Ray Service Map**: Request flow visualization
- **Cost Monitoring**: AWS Cost Explorer integration

## 🔒 Security

### Security Features

- **Input Validation**: Comprehensive Pydantic validation
- **SQL Injection Prevention**: Parameterized DynamoDB queries
- **CORS Configuration**: Proper cross-origin resource sharing
- **Error Handling**: No sensitive data in error responses
- **Dependency Scanning**: Automated vulnerability detection

### Security Scanning

```bash
# Run security scans
task security:scan

# Individual security tools
bandit -r src/              # Static security analysis
safety check               # Dependency vulnerability check
```

## 🔧 Development Tools

### Task Runner Commands

```bash
# Development
task dev                   # Setup development environment
task clean                 # Clean build artifacts
task update:deps          # Update all dependencies

# Code Quality
task lint                  # Run all linting
task format               # Auto-format code
task type:check           # Type checking
task complexity:check     # Complexity analysis

# Testing
task test                 # Run all tests
task test:unit           # Unit tests only
task test:integration    # Integration tests
task test:e2e           # End-to-end tests
task test:benchmark     # Performance tests

# Documentation
task docs:generate       # Generate API docs
task docs:serve         # Serve docs locally
task openapi:validate   # Validate OpenAPI spec

# Infrastructure
task tf:init            # Initialize Terraform
task tf:plan            # Plan infrastructure changes
task tf:apply           # Apply infrastructure changes
task tf:destroy         # Destroy infrastructure

# Deployment
task deploy:dev         # Deploy to development
task deploy:staging     # Deploy to staging
task deploy:prod        # Deploy to production
```

### Pre-commit Hooks

Automatic code quality checks on commit:

- Code formatting with ruff
- Type checking with mypy
- Security scanning with bandit
- Dependency vulnerability checks
- Terraform validation
- Test execution

## 📈 Performance

### Optimizations

- **Cold Start Optimization**: Minimal imports and lazy loading
- **Memory Efficiency**: Optimized Lambda memory allocation
- **Connection Pooling**: Reusable DynamoDB connections
- **Caching**: Configuration and data caching strategies

### Benchmarking

```bash
# Run performance benchmarks
task test:benchmark

# Profile specific functions
task profile:performance
```

## 🤝 Contributing

### Development Workflow

1. **Fork and Clone**: Create your own fork of the repository
2. **Create Branch**: `git checkout -b feature/your-feature`
3. **Setup Environment**: `task dev`
4. **Make Changes**: Implement your feature with tests
5. **Quality Checks**: `task lint` and `task test`
6. **Commit**: Use conventional commits format
7. **Push and PR**: Create a pull request

### Code Style

The project uses modern Python tooling:

- **ruff**: For linting and formatting (replaces black, flake8, isort)
- **mypy**: For type checking
- **pytest**: For testing
- **pre-commit**: For automated quality checks

### Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add new order validation logic
fix: resolve DynamoDB connection timeout
docs: update API documentation
test: add integration tests for order creation
refactor: simplify error handling logic
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

This template is heavily inspired by the excellent [aws-lambda-handler-cookbook](https://github.com/ran-isenberg/aws-lambda-handler-cookbook) by [Ran Isenberg](https://github.com/ran-isenberg). The cookbook provides comprehensive patterns and best practices for AWS Lambda development that are implemented in this template.

Special thanks to:
- [AWS Lambda Powertools](https://github.com/aws-powertools/powertools-lambda-python) team
- [Pydantic](https://github.com/pydantic/pydantic) for excellent data validation
- [UV](https://github.com/astral-sh/uv) for fast Python package management
- [Ruff](https://github.com/astral-sh/ruff) for modern Python tooling

## 📞 Support

- **Documentation**: [Project Wiki](https://github.com/your-org/lambda-python-template/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-org/lambda-python-template/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/lambda-python-template/discussions)
- **Email**: support@example.com

---

**Happy Coding!** 🚀 Start building production-ready serverless applications with confidence.
