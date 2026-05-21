FROM python:3.12-slim AS base

# ── System dependencies ────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    gcc \
    libpq-dev \
    unzip \
    ca-certificates \
    dnsutils \
    nmap \
    masscan \
    libpcap-dev \
    chromium \
    chromium-driver \
    fonts-liberation \
    libatk-bridge2.0-0 \
    libcups2 \
    libgbm1 \
    libnss3 \
    libxss1 \
    libxtst6 \
    && rm -rf /var/lib/apt/lists/*

# ── Nikto (web server scanner) ────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    perl \
    libnet-ssleay-perl \
    libwww-perl \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
ENV NIKTO_PATH=/opt/nikto

# ── Go-based security tools ────────────────────────────────────
ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:$PATH

# Install Go
ARG GO_VERSION=1.22.3
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Install ProjectDiscovery tools
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
    && go install -v github.com/tomnomnom/assetfinder@latest \
    && go install -v github.com/owasp-amass/amass/v4/...@master

# ── Nuclei templates ───────────────────────────────────────────
RUN nuclei -update-templates -silent || true
ENV NUCLEI_TEMPLATES_PATH=/root/nuclei-templates

# ── Python dependencies ────────────────────────────────────────
WORKDIR /app

COPY requirements-workers.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements-workers.txt \
    && rm -f /usr/local/bin/httpx

# ── tldextract data ────────────────────────────────────────────
RUN python -c "import tldextract; tldextract.extract('example.com')"

# ── Copy worker code ───────────────────────────────────────────
COPY . .

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV CHROMIUM_PATH=/usr/bin/chromium
ENV DISPLAY=:99

# Playwright for screenshots
RUN pip install playwright \
    && playwright install chromium \
    && playwright install-deps chromium 2>/dev/null || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

CMD ["python", "-m", "workers.discovery_worker"]
