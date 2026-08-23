FROM node:20-slim

# Install system dependencies (git, curl, gnupg, build-essential)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gnupg \
    python3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install resmi GitHub CLI (gh) tanpa kendala arsitektur dpkg
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package.json
RUN npm install

# Install Wrangler CLI secara global
RUN npm install -g wrangler

COPY . .

EXPOSE 8000
CMD ["npm", "start"]
