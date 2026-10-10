#!/usr/bin/env bash
# ==============================================================================
# VajraNetra Zero Trust Network Access (ZTNA) — One-Command Deployment Script
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "██╗   ██╗ █████╗      ██╗██████╗  █████╗ ███╗   ██╗███████╗████████╗██████╗  █████╗ "
echo "██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗"
echo "██║   ██║███████║     ██║██████╔╝███████║██╔██╗ ██║█████╗     ██║   ██████╔╝███████║"
echo "╚██╗ ██╔╝██╔══██║██   ██║██╔══██╗██╔══██║██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══██║"
echo " ╚████╔╝ ██║  ██║╚█████╔╝██║  ██║██║  ██║██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║"
echo "  ╚═══╝  ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${BLUE}${BOLD}==> Initializing VajraNetra Zero Trust Deployment Engine...${NC}\n"

# 1. Check prerequisites
echo -e "${YELLOW}[1/5] Checking environment prerequisites...${NC}"
for cmd in docker docker-compose; do
    if ! command -v "$cmd" &>/dev/null && ! docker compose version &>/dev/null; then
        echo -e "${RED}[ERROR] '$cmd' is not installed. Please install Docker & Docker Compose first.${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ Docker and Compose detected.${NC}"

# 2. Generate Cryptographic Secrets
echo -e "\n${YELLOW}[2/5] Generating cryptographic keys & secrets...${NC}"
SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')
PEP_SECRET=$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')
POSTGRES_PASS=$(openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(16))')

export SECRET_KEY
export PEP_GATEWAY_SECRET="$PEP_SECRET"
export POSTGRES_PASSWORD="$POSTGRES_PASS"
echo -e "${GREEN}✓ Cryptographic secrets generated.${NC}"

# 3. Deploy container stack
echo -e "\n${YELLOW}[3/5] Launching VajraNetra Zero Trust Stack...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if docker compose version &>/dev/null; then
    docker compose -f docker-compose.prod.yml up -d --build
else
    docker-compose -f docker-compose.prod.yml up -d --build
fi

# 4. Wait for Health Check
echo -e "\n${YELLOW}[4/5] Awaiting service health check...${NC}"
for i in {1..30}; do
    if curl -s -f http://localhost:8000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ VajraNetra Core API is healthy!${NC}"
        break
    fi
    sleep 2
    if [ "$i" -eq 30 ]; then
        echo -e "${YELLOW}⚠️ Core API is taking longer to start, checking container logs...${NC}"
    fi
done

# 5. Summary
echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD} 🎉 VajraNetra Zero Trust Architecture Successfully Deployed!${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "${BOLD}📍 Access URLs:${NC}"
echo -e "   • ${CYAN}Admin SOC Dashboard:${NC}          http://localhost:3000"
echo -e "   • ${CYAN}PDP & ZTNA Core API:${NC}          http://localhost:8000"
echo -e "   • ${CYAN}Drop-In Reverse Proxy Gateway:${NC}http://localhost:8080"
echo -e "   • ${CYAN}Open Policy Agent (OPA):${NC}      http://localhost:8181"
echo -e "   • ${CYAN}SCIM 2.0 User Sync:${NC}           http://localhost:8000/scim/v2/Users"
echo -e "\n${BOLD}🔐 Default Credentials:${NC}"
echo -e "   • Admin:   ${YELLOW}admin / admin123${NC} (or admin@securecorp.local)"
echo -e "   • Analyst: ${YELLOW}analyst / analyst123${NC}"
echo -e "   • User:    ${YELLOW}user / user123${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}\n"
