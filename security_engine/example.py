import json

from security_engine.engine import SecurityEngine


def main() -> None:
    engine = SecurityEngine()

    sample = "Hello, this is a normal security engine test."

    result = engine.analyze(
        content=sample,
        source="local-test",
    )

    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()