from pathlib import Path


def validate_input_file(file_path: str) -> Path:
    """
    Validate that the given path exists and points to a real file.
    Return a Path object if valid.
    Raise an error if invalid.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {file_path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    return path