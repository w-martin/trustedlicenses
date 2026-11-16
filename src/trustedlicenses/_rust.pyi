# Type stub for the `trustedlicenses._rust` extension module.

# Run the command line with `argv` (program name first); returns the exit status.
def main(argv: list[str]) -> int: ...

# Run the command line with `argv`; returns (exit status, standard output, standard error).
def run_captured(argv: list[str]) -> tuple[int, str, str]: ...
