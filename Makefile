.PHONY: dev test lint fmt package clean

# Editable install with dev dependencies (pytest, ruff, httpx)
dev:
	python3 -m venv venv
	./venv/bin/pip install -e ".[dev]"
	@echo ""
	@echo "Activate with: source venv/bin/activate"
	@echo "Run the dashboard with: make run"

run:
	OMENWATCH_DB=./data/omenwatch.db PYTHONPATH=. \
		venv/bin/uvicorn omenwatch.app:app --reload --port 7373

test:
	PYTHONPATH=. python3 -m pytest tests/ -v

lint:
	ruff check omenwatch/ tests/

fmt:
	ruff check --fix omenwatch/ tests/
	ruff format omenwatch/ tests/

package:
	./build.sh all

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ .pytest_cache/ .ruff_cache/ *.egg-info
