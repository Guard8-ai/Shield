# Shield - Multi-language Development Container
# Use for testing cross-language interoperability

FROM ubuntu:22.04

LABEL maintainer="Guard8.ai <dev@guard8.ai>"
LABEL description="Shield encryption library development environment"

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    pkg-config \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    golang-go \
    default-jdk \
    gradle \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /shield

# Copy source code
COPY . .

# Install Python dependencies
RUN cd python && pip3 install -e ".[dev]"

# Install JavaScript dependencies
RUN cd javascript && npm ci

# Run all tests by default
CMD ["bash", "-c", "\
    echo '=== Rust Tests ===' && cd shield-core && cargo test --features async && \
    echo '=== Python Tests ===' && cd ../python && python3 -m pytest && \
    echo '=== JavaScript Tests ===' && cd ../javascript && npm test && \
    echo '=== Go Tests ===' && cd ../go && go test ./... && \
    echo '=== All tests passed! ===' \
"]
