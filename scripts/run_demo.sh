#!/usr/bin/env bash
# ============================================================
# ULPF Quick Demo Runner
# Runs the complete E2E demo with all services
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "============================================================"
echo "ULPF Quick Demo Runner"
echo "============================================================"
echo ""

# Check if docker compose is running
if ! docker compose -f "$PROJECT_ROOT/docker-compose.airgap.yml" ps | grep -q "Up"; then
    echo "Starting infrastructure..."
    cd "$PROJECT_ROOT"
    docker compose -f docker-compose.airgap.yml up -d
    
    echo "Waiting for services to be healthy..."
    sleep 30
fi

# Check if backend API is running
echo "Checking backend API..."
if ! curl -s http://localhost:5000/api/v1/health > /dev/null; then
    echo "Starting backend API..."
    cd "$PROJECT_ROOT/backend"
    python -m ulpf.api &
    API_PID=$!
    sleep 5
fi

# Check if pipeline is running
echo "Checking pipeline..."
if ! curl -s http://localhost:5000/api/v1/health | grep -q "parser engine.*healthy"; then
    echo "Starting pipeline runner..."
    cd "$PROJECT_ROOT/backend"
    python -m ulpf.orchestrator &
    PIPELINE_PID=$!
    sleep 10
fi

# Run the demo
echo ""
echo "Running E2E demo..."
cd "$PROJECT_ROOT"
python scripts/demo_e2e.py

DEMO_EXIT=$?

echo ""
if [ $DEMO_EXIT -eq 0 ]; then
    echo "✅ Demo completed successfully!"
else
    echo "❌ Demo failed with exit code $DEMO_EXIT"
fi

exit $DEMO_EXIT