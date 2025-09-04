FROM python:3.11

# Install system dependencies including those needed for Slither and Mythril
RUN apt-get update && apt-get install -y \
    curl wget \
    git \
    build-essential \
    gnupg \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js LTS version (for better Hardhat compatibility)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - \
    && apt-get update && apt-get install -y nodejs

# Install Slither (requires Python)
RUN pip install slither-analyzer

# Install Mythril (will use bytecode analysis to avoid solc compatibility issues)
RUN pip install mythril

# Install Node.js tools and OpenZeppelin contracts globally
RUN npm install -g hardhat solhint@latest

# Create a global node_modules directory for OpenZeppelin
RUN mkdir -p /usr/local/lib/node_modules_global
WORKDIR /usr/local/lib/node_modules_global
RUN npm init -y && npm install @openzeppelin/contracts
ENV NODE_PATH=/usr/local/lib/node_modules_global/node_modules

# Set working directory back to /analysis
WORKDIR /analysis

# Copy and install requirements
COPY requirements.txt /analysis/
RUN pip install --no-cache-dir -r /analysis/requirements.txt

# Copy application code into /analysis
COPY . /analysis/

# Create reports directory
RUN mkdir -p /analysis/reports

# Run analyze.py (must have no config.py import)
ENTRYPOINT ["python", "analyze.py"]