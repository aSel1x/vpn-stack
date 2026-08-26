from pathlib import Path


def read(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def set_key(path: Path, key: str, value: str) -> None:
    values = read(path)
    values[key] = value
    lines = [f"{k}={v}" for k, v in values.items()]
    path.write_text("\n".join(lines) + "\n")


def get_or_create(path: Path, key: str, default_factory) -> str:
    values = read(path)
    if key in values and values[key]:
        return values[key]
    value = default_factory()
    set_key(path, key, value)
    return value
