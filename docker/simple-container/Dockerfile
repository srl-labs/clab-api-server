FROM debian:bookworm-slim

# Set noninteractive frontend for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# The container image is expected to be reached through its Docker network or
# host-network namespace. Native/systemd installs keep the safer loopback default.
ENV API_LISTEN_ADDRESS=0.0.0.0

# Install base dependencies and required tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg \
    lsb-release \
    libpam0g-dev \
    login \
    # Containerlab deps & general utils
    bash \
    iproute2 \
    sudo \
    procps \
    openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Install Docker CLI only (since we'll use the host's Docker daemon)
RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
RUN chmod a+r /etc/apt/keyrings/docker.asc
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker-ce-cli \
    docker-compose-plugin \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ARG to specify the target architecture (automatically set by Buildx)
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64|arm64) ;; \
      "") echo "TARGETARCH must be set by Buildx" >&2; exit 1 ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac

# Copy the correct pre-built binary based on the target architecture
COPY dist/clab-api-server-linux-${TARGETARCH} /usr/local/bin/clab-api-server
RUN chmod +x /usr/local/bin/clab-api-server && \
    /usr/local/bin/clab-api-server -v

# Copy entrypoint script
COPY docker/simple-container/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default command passed to our entrypoint script
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["clab-api-server"]
