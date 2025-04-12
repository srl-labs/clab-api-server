# Build stage
FROM golang:1.24

# Install system dependencies
RUN apt update && apt install -y --no-install-recommends \
    build-essential \
    libpam-dev

# Set working directory
WORKDIR /app

CMD ["go", "build", "-buildvcs=false", "-o", "clab-api-server", "./cmd/server"]
