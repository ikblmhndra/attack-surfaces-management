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
    libpcap-dev \
    tini \
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

# ── Go-based security tools ────────────────────────────────────
ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:$PATH

# Install Go
ARG GO_VERSION=1.22.3
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# Install ProjectDiscovery tools (pinned — `@latest`/`@master` let every rebuild
# silently change scan behavior with no changelog of which tool version produced
# a given finding)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0 \
    && go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 \
    && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.0 \
    && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 \
    && go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3 \
    && go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@v1.2.2 \
    && go install -v github.com/projectdiscovery/katana/cmd/katana@v1.6.1 \
    && go install -v github.com/lc/gau/v2/cmd/gau@v2.2.4 \
    && go install -v github.com/ffuf/ffuf/v2@v2.1.0 \
    && go install -v github.com/PentestPad/subzy@v1.2.1 \
    && go install -v github.com/tomnomnom/assetfinder@v0.1.1 \
    && go install -v github.com/owasp-amass/amass/v4/...@v4.2.0 \
    && go install -v github.com/tomnomnom/waybackurls@v0.1.0 \
    && go install -v github.com/lc/subjs@v1.0.1 \
    && go install -v github.com/hahwul/dalfox/v2@v2.9.2 \
    && go install -v github.com/hakluke/hakrawler@latest \
    && go install -v github.com/003random/getJS/v2@latest \
    && go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest

# ── Bug bounty active-exploit tools (pinned) ───────────────────
# sqlmap runs as a script (invoked via `python /opt/sqlmap/sqlmap.py`), not a
# packaged binary; arjun is a pip tool. Both are consumed only by the bounty
# pipeline's exploit worker, which re-validates scope before invoking them.
RUN git clone --depth 1 --branch 1.10.7 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ENV SQLMAP_PATH=/opt/sqlmap/sqlmap.py

# ── Extended bug-bounty recon/discovery tools ──────────────────
# feroxbuster (recursive content discovery) via the official installer; uro
# (URL dedup), waymore (extra historical URL sources), wafw00f (WAF fingerprint)
# are pip tools. gf-style URL classification and qsreplace-style payload
# injection are done in Python (workers/bounty/*), not as binaries -- fewer
# moving parts and no gf-pattern-repo dependency.
RUN cd /usr/local/bin && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
RUN pip install --no-cache-dir uro==1.0.2 waymore==8.9 wafw00f==2.4.2

# ── Nuclei templates ───────────────────────────────────────────
RUN nuclei -update-templates -silent || true
ENV NUCLEI_TEMPLATES_PATH=/root/nuclei-templates

# ── Tool configuration ─────────────────────────────────────────
COPY config/gau.toml /root/.gau.toml

# ── Python dependencies ────────────────────────────────────────
WORKDIR /app

COPY requirements-workers.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements-workers.txt \
    && rm -f /usr/local/bin/httpx \
    && ln -sf /go/bin/subfinder /usr/local/bin/subfinder \
    && ln -sf /go/bin/assetfinder /usr/local/bin/assetfinder \
    && ln -sf /go/bin/amass /usr/local/bin/amass \
    && ln -sf /go/bin/dnsx /usr/local/bin/dnsx \
    && ln -sf /go/bin/tlsx /usr/local/bin/tlsx \
    && ln -sf /go/bin/naabu /usr/local/bin/naabu \
    && ln -sf /go/bin/httpx /usr/local/bin/httpx \
    && ln -sf /go/bin/katana /usr/local/bin/katana \
    && ln -sf /go/bin/gau /usr/local/bin/gau \
    && ln -sf /go/bin/ffuf /usr/local/bin/ffuf \
    && ln -sf /go/bin/subzy /usr/local/bin/subzy \
    && ln -sf /go/bin/nuclei /usr/local/bin/nuclei \
    && ln -sf /go/bin/dalfox /usr/local/bin/dalfox \
    && pip install --no-cache-dir arjun==2.2.7

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

# Real liveness check: BaseWorker.run() touches this file every ~20s while its
# RabbitMQ connection is alive (see workers/base_worker.py). A hung event loop or
# dropped connection means the file goes stale and this check starts failing.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD find /tmp/worker_heartbeat -mmin -1 2>/dev/null | grep -q . || exit 1

# tini as PID 1: headless Chromium (run_dom_xss, screenshot workers) forks a
# process tree that's normally reaped by its parent -- without a real init,
# a killed/crashed browser leaves those as permanent zombies here, since a
# bare `python -m ...` PID 1 never reaps processes it didn't itself spawn.
ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "workers.discovery_worker"]
