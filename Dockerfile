FROM node:20-slim

# Install system dependencies (git, curl, build-tools, GitHub CLI)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    gnupg \
    python3 \
    build-essential \
    && mkdir -p -m 755 /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package.json
RUN npm install

# Install Wrangler CLI secara global
RUN npm install -g wrangler

COPY . .

EXPOSE 8000
CMD ["npm", "start"]
