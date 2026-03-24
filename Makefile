.PHONY: help install test lint format type-check clean demo neo4j

help:
	@echo "Zeropath Development Commands"
	@echo "=============================="
	@echo ""
	@echo "Setup & Installation:"
	@echo "  make install          Install in development mode"
	@echo "  make install-deps     Install production dependencies only"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run all tests"
	@echo "  make test-verbose     Run tests with verbose output"
	@echo "  make coverage         Generate coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint             Run all linters"
	@echo "  make format           Format code with black and isort"
	@echo "  make type-check       Run mypy type checking"
	@echo "  make ruff             Run ruff linter/fixer"
	@echo ""
	@echo "Development:"
	@echo "  make demo             Run demo analysis"
	@echo "  make neo4j            Start Neo4j in Docker"
	@echo "  make clean            Remove build artifacts"
	@echo ""

install:
	python3 -m pip install -e ".[dev]"

install-deps:
	python3 -m pip install -e .

test:
	python3 -m pytest tests/ -v

test-verbose:
	python3 -m pytest tests/ -vv --tb=short

coverage:
	python3 -m pytest tests/ --cov=src/zeropath --cov-report=html
	@echo "Coverage report generated in htmlcov/index.html"

lint: format type-check ruff
	@echo "All linting passed!"

format:
	python3 -m black src/ tests/
	python3 -m isort src/ tests/
	@echo "Code formatted with black and isort"

type-check:
	python3 -m mypy src/zeropath/ --strict
	@echo "Type checking passed!"

ruff:
	python3 -m ruff check src/ tests/
	@echo "Ruff checks passed!"

ruff-fix:
	python3 -m ruff check --fix src/ tests/

demo:
	@echo "Analyzing example contracts..."
	@mkdir -p output
	python3 -m zeropath.cli analyze example_contracts/SimpleToken.sol -o output/graph.json
	@echo "✓ Analysis complete - output saved to output/graph.json"
	@echo ""
	@echo "Graph summary:"
	@python3 -c "import json; data = json.load(open('output/graph.json')); print(f\"  Contracts: {len(data['contracts'])}\\n  Functions: {len(data['functions'])}\\n  State vars: {len(data['state_variables'])}\\n  Calls: {len(data['function_calls'])}\")"

neo4j:
	@echo "Starting Neo4j container..."
	docker run -d \
		--name zeropath-neo4j \
		-p 7687:7687 \
		-p 7474:7474 \
		-e NEO4J_AUTH=neo4j/password \
		neo4j:5.15
	@echo "✓ Neo4j started"
	@echo "  URI: bolt://localhost:7687"
	@echo "  Browser: http://localhost:7474"
	@echo "  Username: neo4j"
	@echo "  Password: password"

neo4j-stop:
	@echo "Stopping Neo4j container..."
	docker stop zeropath-neo4j && docker rm zeropath-neo4j
	@echo "✓ Neo4j stopped"

neo4j-logs:
	docker logs -f zeropath-neo4j

clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	@echo "✓ Cleaned"

docs:
	@echo "Building documentation..."
	@echo "Documentation is in docs/ directory"

.DEFAULT_GOAL := help
