FROM debian:bookworm-slim

# Set noninteractive frontend for apt-get
ENV DEBIAN_FRONTEND=noninteractive

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
 && rm -rf /var/lib/apt/lists/*

# User setup
ARG API_USER=admin
ARG API_PASS=admin
RUN groupadd --system docker && \
    useradd -m -s /bin/bash ${API_USER} && \
    (getent group clab_admins || groupadd clab_admins) && \
    usermod -aG clab_admins,docker ${API_USER} && \
    usermod -aG clab_admins,docker root && \
    echo "${API_USER}:${API_PASS}" | chpasswd && \
    echo "INFO: Created user '${API_USER}' with provided password."

WORKDIR /app

# ARG to specify the target architecture (automatically set by Buildx)
ARG TARGETARCH=amd64

# Copy the correct pre-built binary based on the target architecture
COPY dist/clab-api-server-linux-${TARGETARCH} /usr/local/bin/clab-api-server
RUN chmod +x /usr/local/bin/clab-api-server

# Copy the example .env file to provide configuration
COPY docker/common/.env.example /app/.env

# Copy entrypoint script
COPY docker/simple-container/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Default command passed to our entrypoint script
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["clab-api-server"]