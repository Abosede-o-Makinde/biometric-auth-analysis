.PHONY: install dev lint fmt test smoke serve clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

lint:
	ruff check biometric_auth tests
	ruff format --check biometric_auth tests

fmt:
	ruff format biometric_auth tests
	ruff check --fix biometric_auth tests

test:
	python3 -m pytest tests/ -q

test-cov:
	python3 -m pytest tests/ --cov=biometric_auth --cov-report=html

smoke:
	biometric-auth evaluate --scores data/synthetic/scores_high_accuracy.csv --output /tmp/bio_high.json
	biometric-auth evaluate --scores data/synthetic/scores_low_accuracy.csv  --output /tmp/bio_low.json
	biometric-auth gdpr --config data/sample_configs/system_face_recognition.yaml --output /tmp/bio_gdpr.json
	@python3 -c "import json; r=json.load(open('/tmp/bio_high.json')); assert r['eer'] < 0.03, f'EER={r[\"eer\"]}'; print('High-accuracy EER OK:', r['eer'])"
	@python3 -c "import json; r=json.load(open('/tmp/bio_low.json'));  assert r['eer'] > 0.10, f'EER={r[\"eer\"]}'; print('Low-accuracy EER OK:',  r['eer'])"
	@python3 -c "import json; r=json.load(open('/tmp/bio_gdpr.json')); assert 'overall_score' in r; print('GDPR report OK, score:', r['overall_score'])"

serve:
	biometric-auth serve

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache htmlcov .coverage dist build
