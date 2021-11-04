# Indy port

Chunks of code ported from [Hyperledger Ursa](https://github.com/hyperledger/ursa).

## Run tests

- Data used in tests are found under [data/tests](data/tests/)
- Test vectors are from [Ursa](https://github.com/hyperledger/ursa)

Prep:

```
python -m venv env
source env/bin/activate
pip install pytest
```

Run all tests:

```
pytest test -v
```

Run specific test by name:

```
pytest test -v -k test_verify_equality
```

In order to not suppress `stdout` from `print` and whatnot, pass `-s` to any of
the `pytest` commands.
