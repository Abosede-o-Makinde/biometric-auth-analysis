# Contributing

Thank you for contributing to `biometric-auth-analysis`.

## Quick start

```bash
git clone https://github.com/Abosede-o-Makinde/biometric-auth-analysis
cd biometric-auth-analysis
pip install -e ".[dev]"
python3 -m pytest tests/ -q      # all tests should pass
```

## Adding a new GDPR Art.9 check

1. Open `biometric_auth/engine/gdpr.py`
2. Write a pure function with the signature:
   ```python
   def _check_a9_0xx(
       config: SystemConfig,
       evaluation_result: Optional[EvaluationResult] = None,
       bias_result: Optional[BiasResult] = None,
       attack_result: Optional[AttackResult] = None,
   ) -> Art9CheckResult:
   ```
3. Append it to the relevant `_OBLIGATIONS` tuple
4. Add `SystemConfig` fields if needed (all must be `Optional`)
5. Write a test assertion in `tests/test_gdpr.py`
6. Cite the GDPR provision in the docstring and `docs/GDPR_BIOMETRIC_REFERENCE.md`

## Adding a new attack vector

1. Append an `_AttackSpec` to `_ATTACK_SPECS` in `engine/attack.py`
2. Add a `_mitigations_<id>()` helper if needed
3. Update `docs/METHODOLOGY.md` §4 with the reference

## Adding a new metric or statistical method

1. Add a pure function to `engine/metrics.py` or `engine/statistics.py`
2. Write tests in `tests/test_metrics.py` or `tests/test_statistics.py`
3. Cite the source method in the docstring

## Branch naming

```
feature/<description>   — new capability
fix/<description>       — bug fix
docs/<description>      — documentation only
```

## Commit style

```
feat: add A9-045 check for biometric data portability
fix: correct DeLong variance formula for edge case m=1
docs: add ISO 30107-3 reference to METHODOLOGY
test: add DIR=1.0 assertion for identical group distributions
```

## Pull request checklist

- [ ] All tests pass (`pytest tests/ -q`)
- [ ] `ruff check` and `ruff format --check` pass
- [ ] New check/metric has a test assertion
- [ ] GDPR provisions cited in docstrings
- [ ] `docs/METHODOLOGY.md` or `docs/GDPR_BIOMETRIC_REFERENCE.md` updated if applicable
- [ ] PR template completed (score impact table filled in)
