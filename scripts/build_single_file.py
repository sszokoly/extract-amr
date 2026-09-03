"""Build a compressed single-file bundle of extract-amr.

The bundle concatenates every runtime module of the package in dependency
order into one flat source file, strips intra-package imports, compresses
the result with zlib, and wraps it in a small base64 launcher script.

The target platform is an appliance venv (Python 3.8) that already
provides Click and Scapy; those dependencies stay imported, not bundled.
The original package files are never modified.

Usage:

    uv run python scripts/build_single_file.py [options]
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata
import zlib
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO_ROOT / "extract_amr"

MODULE_ORDER = [
    "bundle_validity",
    "models",
    "errors",
    "bits",
    "codec",
    "rtp",
    "capture",
    "rfc4867",
    "storage",
    "discovery",
    "timeline",
    "api",
    "cli",
]

EXCLUDED_MODULES = {"__init__", "__main__"}

SMOKE_CASES = [
    (
        "tests/fixtures/directional_modes.pcap",
        ".amr",
        [
            "--src-address",
            "192.0.2.1",
            "--dst-address",
            "192.0.2.2",
            "--src-port",
            "4000",
            "--dst-port",
            "5000",
            "--ssrc",
            str(0x11111111),
            "--payload-type",
            "96",
            "--codec",
            "amr",
            "--mode",
            "octet-aligned",
        ],
    ),
    (
        "tests/fixtures/directional_modes.pcap",
        ".awb",
        [
            "--src-address",
            "192.0.2.2",
            "--dst-address",
            "192.0.2.1",
            "--src-port",
            "5000",
            "--dst-port",
            "4000",
            "--ssrc",
            str(0x11111111),
            "--payload-type",
            "96",
            "--codec",
            "amr-wb",
            "--mode",
            "bandwidth-efficient",
        ],
    ),
]

BUNDLE_NAME = "extract-amr.py"
FLAT_NAME = "extract-amr.flat.py"
KDF_ITERATIONS = 600_000
KDF_SALT_BYTES = 16


class BuildError(Exception):
    """A bundle build or verification step failed."""


def module_path(name: str) -> Path:
    return PACKAGE_DIR / f"{name}.py"


def load_module_source(name: str) -> str:
    path = module_path(name)
    if not path.is_file():
        raise BuildError(f"missing module file: {path}")
    return path.read_text(encoding="utf-8")


def parse_module(name: str) -> ast.Module:
    source = load_module_source(name)
    try:
        return ast.parse(source)
    except SyntaxError as error:
        raise BuildError(f"cannot parse {module_path(name)}: {error}") from error


def check_order_covers_package() -> None:
    actual = {path.stem for path in PACKAGE_DIR.glob("*.py") if path.stem not in EXCLUDED_MODULES}
    listed = set(MODULE_ORDER)
    missing = sorted(actual - listed)
    extra = sorted(listed - actual)
    if missing or extra:
        details = []
        if missing:
            details.append(f"not listed: {missing}")
        if extra:
            details.append(f"listed but absent: {extra}")
        raise BuildError(
            "MODULE_ORDER does not match the package modules (" + "; ".join(details) + ")"
        )


def relative_import_targets(tree: ast.Module) -> List[str]:
    targets: List[str] = []
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom) or node.level == 0:
            continue
        if node.module is None:
            targets.extend(
                alias.name.split(".")[0] for alias in node.names if alias.name != "__version__"
            )
        else:
            targets.append(node.module.split(".")[0])
    return targets


def check_dependency_order() -> None:
    position = {name: index for index, name in enumerate(MODULE_ORDER)}
    for name in MODULE_ORDER:
        tree = parse_module(name)
        for target in relative_import_targets(tree):
            if target not in position:
                raise BuildError(f"extract_amr.{name} imports unknown module '{target}'")
            if position[target] >= position[name]:
                raise BuildError(
                    f"extract_amr.{name} imports extract_amr.{target}, "
                    "which is not earlier in MODULE_ORDER"
                )


def top_level_names(tree: ast.Module) -> set:
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(target.id for target in node.targets if isinstance(target, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def check_name_collisions() -> None:
    seen: Dict[str, str] = {}
    for name in MODULE_ORDER:
        for symbol in top_level_names(parse_module(name)):
            if symbol in seen:
                raise BuildError(
                    f"top-level name '{symbol}' defined in both "
                    f"extract_amr.{seen[symbol]} and extract_amr.{name}"
                )
            seen[symbol] = name


def strip_relative_imports(name: str) -> str:
    source = load_module_source(name)
    tree = ast.parse(source)
    spans = [
        (
            node.lineno,
            node.end_lineno if node.end_lineno is not None else node.lineno,
        )
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and (node.level > 0 or node.module == "__future__")
    ]
    drop = {line_number for start, end in spans for line_number in range(start, end + 1)}
    kept = [line for number, line in enumerate(source.splitlines(), start=1) if number not in drop]
    return normalize_blank_lines(kept)


def normalize_blank_lines(lines: List[str]) -> str:
    normalized: List[str] = []
    blanks = 0
    for line in lines:
        blanks = blanks + 1 if not line.strip() else 0
        if blanks <= 2:
            normalized.append(line)
    text = "\n".join(normalized).strip("\n")
    return text + "\n" if text else ""


def read_version() -> str:
    for line in load_module_source("__init__").splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"')
    raise BuildError("could not read __version__ from __init__.py")


def assemble_flat_source(validity: Optional[float] = None) -> str:
    header = [
        '"""extract-amr single-file flat source (generated).',
        "",
        "Concatenation of the extract_amr package in dependency order.",
        "Regenerate with scripts/build_single_file.py --keep-flat.",
        '"""',
        "from __future__ import annotations",
        f'__version__ = "{read_version()}"',
    ]
    if validity is not None:
        header.append(f"VALIDITY = {validity!r}")
    chunks: List[str] = ["\n".join(header)]
    for name in MODULE_ORDER:
        banner = "\n".join(
            [
                "# " + "-" * 66,
                f"# extract_amr.{name}",
                "# " + "-" * 66,
            ]
        )
        chunks.append(banner + "\n" + strip_relative_imports(name).rstrip("\n"))
        if name == "bundle_validity" and validity is not None:
            chunks.append("_enforce_bundle_validity(VALIDITY)")
    chunks.append('if __name__ == "__main__":\n    cli()')
    return "\n\n\n".join(chunks) + "\n"


def normalize_passphrase(passphrase: str) -> str:
    normalized = unicodedata.normalize("NFC", passphrase)
    if not normalized:
        raise BuildError("--enc-passphrase must not be empty")
    if not all(character.isprintable() for character in normalized):
        raise BuildError("--enc-passphrase must contain only printable characters")
    return normalized


def derive_fernet_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError as error:
        raise BuildError(
            "--enc-passphrase requires Cryptography; install the 'encryption' extra"
        ) from error

    normalized = normalize_passphrase(passphrase)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(normalized.encode("utf-8")))


def encrypted_payload(wrapped_blob: bytes, passphrase: str, salt: bytes) -> bytes:
    try:
        from cryptography.fernet import Fernet
    except ImportError as error:
        raise BuildError(
            "--enc-passphrase requires Cryptography; install the 'encryption' extra"
        ) from error

    return Fernet(derive_fernet_key(passphrase, salt, KDF_ITERATIONS)).encrypt(wrapped_blob)


def wrap_launcher(
    flat_source: str,
    shebang: Optional[str],
    encryption_passphrase: Optional[str] = None,
) -> str:
    blob = base64.encodebytes(zlib.compress(flat_source.encode("utf-8"), 9))
    encrypted = encryption_passphrase is not None
    salt: Optional[bytes] = None
    if encrypted:
        salt = os.urandom(KDF_SALT_BYTES)
        blob_text = encrypted_payload(blob, encryption_passphrase, salt).decode("ascii")
        blob_lines = [blob_text[index : index + 76] for index in range(0, len(blob_text), 76)]
    else:
        blob_lines = blob.decode("ascii").splitlines()
    lines: List[str] = []
    if shebang:
        lines.append(f"#!{shebang}")
    payload_description = (
        "The flat extract-amr source is zlib-compressed, base64-encoded, and\n"
        "Fernet-encrypted below. Regenerate with scripts/build_single_file.py."
        if encrypted
        else "The flat extract-amr source is zlib-compressed and base64-encoded\n"
        "below. Regenerate with scripts/build_single_file.py.\n\n"
    )
    author_description = "Author: Sabi Szokoly\nContact: https://github.com/sszokoly\n"
    lines.extend(
        [
            '"""extract-amr single-file bundle (generated; do not edit).',
            "",
            *payload_description.splitlines(),
            *author_description.splitlines(),
            '"""',
            "import base64",
        ]
    )
    if encrypted:
        lines.extend(["import getpass", "import unicodedata", "from pathlib import Path"])
    lines.extend(["import sys", "import traceback", "import zlib", "", ""])
    if encrypted and salt is not None:
        encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii")
        lines.extend(
            [
                f'KDF_SALT = "{encoded_salt}"',
                f"KDF_ITERATIONS = {KDF_ITERATIONS}",
                "_MISSING_PASSPHRASE = object()",
                "",
                "",
            ]
        )
    lines.append('COMPRESSED_SCRIPT = """\\')
    lines.extend(blob_lines)
    lines.extend(
        [
            '"""',
            "",
            "",
            "def unwrap_and_decompress(wrapped_text):",
            '    """Unwraps, base64 decodes and decompresses string."""',
            '    base64_str = wrapped_text.replace("\\n", "")',
            "    compressed_bytes = base64.b64decode(base64_str)",
            "    original_string = zlib.decompress(compressed_bytes)",
            '    return original_string.decode("utf-8")',
        ]
    )
    if encrypted:
        lines.extend(
            [
                "",
                "",
                "def extract_runtime_passphrase(arguments):",
                '    """Removes and returns the launcher-only passphrase option."""',
                "    passphrase = _MISSING_PASSPHRASE",
                "    sanitized = [arguments[0]]",
                "    index = 1",
                "    while index < len(arguments):",
                "        argument = arguments[index]",
                '        if argument == "--":',
                "            sanitized.extend(arguments[index:])",
                "            break",
                '        if argument == "--enc-passphrase":',
                "            if passphrase is not _MISSING_PASSPHRASE:",
                '                raise ValueError("duplicate --enc-passphrase")',
                '            if index + 1 >= len(arguments) or arguments[index + 1] == "--":',
                '                raise ValueError("missing --enc-passphrase value")',
                "            next_argument = arguments[index + 1]",
                '            if next_argument == "--enc-passphrase" or next_argument.startswith(',
                '                "--enc-passphrase="',
                "            ):",
                '                raise ValueError("duplicate --enc-passphrase")',
                "            passphrase = next_argument",
                "            index += 2",
                "            continue",
                '        if argument.startswith("--enc-passphrase="):',
                "            if passphrase is not _MISSING_PASSPHRASE:",
                '                raise ValueError("duplicate --enc-passphrase")',
                '            passphrase = argument.split("=", 1)[1]',
                "            index += 1",
                "            continue",
                "        sanitized.append(argument)",
                "        index += 1",
                "    return passphrase, sanitized",
                "",
                "",
                "def read_dotenv_passphrase():",
                '    """Reads the passphrase from the launcher\'s sibling .env file."""',
                "    try:",
                "        from dotenv import dotenv_values",
                "    except ImportError:",
                "        return _MISSING_PASSPHRASE",
                "    try:",
                "        values = dotenv_values(",
                '            Path(__file__).resolve().with_name(".env"), interpolate=False',
                "        )",
                "    except OSError:",
                "        return _MISSING_PASSPHRASE",
                '    if "ENC_PASSPHRASE" not in values:',
                "        return _MISSING_PASSPHRASE",
                '    return values["ENC_PASSPHRASE"]',
                "",
                "",
                "def resolve_passphrase() -> str:",
                '    """Selects dotenv, command-line, or prompted passphrase input."""',
                "    try:",
                "        runtime_passphrase, sanitized = extract_runtime_passphrase(sys.argv)",
                "    except ValueError:",
                '        print("error: invalid --enc-passphrase argument", file=sys.stderr)',
                "        raise SystemExit(2)",
                "    sys.argv[:] = sanitized",
                "    dotenv_passphrase = read_dotenv_passphrase()",
                "    if dotenv_passphrase is not _MISSING_PASSPHRASE:",
                "        passphrase = dotenv_passphrase",
                "    elif runtime_passphrase is not _MISSING_PASSPHRASE:",
                "        passphrase = runtime_passphrase",
                "    else:",
                '        passphrase = getpass.getpass("Encryption passphrase: ")',
                "    if not isinstance(passphrase, str):",
                '        raise ValueError("invalid passphrase")',
                "    return passphrase",
                "",
                "",
                "def decrypt_script(encrypted_text):",
                '    """Resolves a passphrase and decrypts the wrapped script."""',
                "    try:",
                "        from cryptography.fernet import Fernet, InvalidToken",
                "        from cryptography.hazmat.primitives import hashes",
                "        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC",
                "    except ImportError:",
                '        print("error: encrypted bundle requires Cryptography", file=sys.stderr)',
                "        raise SystemExit(1)",
                "    try:",
                "        passphrase = resolve_passphrase()",
                '        passphrase = unicodedata.normalize("NFC", passphrase)',
                "        if not passphrase:",
                '            raise ValueError("invalid passphrase")',
                "        if not all(char.isprintable() for char in passphrase):",
                '            raise ValueError("invalid passphrase")',
                '        salt = base64.urlsafe_b64decode(KDF_SALT.encode("ascii"))',
                "        kdf = PBKDF2HMAC(",
                "            algorithm=hashes.SHA256(),",
                "            length=32,",
                "            salt=salt,",
                "            iterations=KDF_ITERATIONS,",
                "        )",
                '        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))',
                '        token = encrypted_text.replace("\\n", "").encode("ascii")',
                '        return Fernet(key).decrypt(token).decode("ascii")',
                "    except EOFError:",
                '        print("error: unable to read encryption passphrase", file=sys.stderr)',
                "        raise SystemExit(1)",
                "    except (InvalidToken, TypeError, UnicodeError, ValueError):",
                '        print("error: decryption failed", file=sys.stderr)',
                "        raise SystemExit(1)",
            ]
        )
    lines.extend(["", "", 'if __name__ == "__main__":'])
    if encrypted:
        lines.append("    wrapped_script = decrypt_script(COMPRESSED_SCRIPT)")
    else:
        lines.append("    wrapped_script = COMPRESSED_SCRIPT")
    lines.append("    script_content = unwrap_and_decompress(wrapped_script)")
    lines.extend(
        [
            "    try:",
            '        code = compile(script_content, "<extract-amr>", "exec")',
            "        exec(code)",
            "    except SystemExit:",
            "        raise",
            "    except KeyboardInterrupt:",
            "        raise",
            "    except Exception:",
            "        traceback.print_exc()",
            "        raise SystemExit(1)",
        ]
    )
    return "\n".join(lines) + "\n"


def run_command(command: List[str], label: str, input_text: Optional[str] = None) -> None:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        input=input_text.encode("utf-8") if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=input_text is not None,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        raise BuildError(f"{label} failed with exit code {result.returncode}")


def smoke_verify(bundle_path: Path, encryption_passphrase: Optional[str] = None) -> None:
    passphrase_input = f"{encryption_passphrase}\n" if encryption_passphrase is not None else None
    temporary_directory = None
    smoke_bundle = bundle_path
    if encryption_passphrase is not None:
        temporary_directory = tempfile.TemporaryDirectory(prefix="extract-amr-smoke-")
        smoke_bundle = Path(temporary_directory.name) / bundle_path.name
        shutil.copy2(bundle_path, smoke_bundle)
    try:
        print("smoke: --help")
        run_command(
            [sys.executable, str(smoke_bundle), "--help"],
            "--help smoke",
            passphrase_input,
        )

        for capture, extension, selector_arguments in SMOKE_CASES:
            capture_path = REPO_ROOT / capture
            if not capture_path.is_file():
                raise BuildError(f"smoke fixture missing: {capture_path}")
            reference = capture_path.with_suffix(f".reference{extension}")
            bundled = capture_path.with_suffix(f".bundled{extension}")
            print(f"smoke: extract {capture}")
            run_command(
                [
                    sys.executable,
                    "-m",
                    "extract_amr",
                    "extract",
                    str(capture_path),
                    *selector_arguments,
                    "--output",
                    str(reference),
                ],
                f"reference extraction for {capture}",
            )
            run_command(
                [
                    sys.executable,
                    str(smoke_bundle),
                    "extract",
                    str(capture_path),
                    *selector_arguments,
                    "--output",
                    str(bundled),
                ],
                f"bundle extraction for {capture}",
                passphrase_input,
            )
            if reference.read_bytes() != bundled.read_bytes():
                raise BuildError(f"bundle output differs for {capture}")
            reference.unlink()
            bundled.unlink()
    finally:
        if temporary_directory is not None:
            temporary_directory.cleanup()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit_readme(output_dir: Path, shebang: Optional[str], encrypted: bool) -> None:
    python = shebang or "python3"
    passphrase_notes = ""
    if encrypted:
        passphrase_notes = (
            "\n"
            "## Encryption passphrase\n"
            "\n"
            "The encrypted launcher checks these passphrase sources in order:\n"
            "\n"
            "1. `ENC_PASSPHRASE` in `.env` beside the resolved launcher path.\n"
            "2. `--enc-passphrase VALUE` or `--enc-passphrase=VALUE`.\n"
            "3. A hidden interactive prompt.\n"
            "\n"
            "Dotenv support is optional. Install it with `python -m pip install "
            "python-dotenv`, create the sibling `.env`, and restrict its permissions, "
            "for example with `chmod 600 .env`. The dotenv value is not exported to the "
            "application environment.\n"
            "\n"
            "Command-line passphrases may be retained in shell history and exposed "
            "through operating-system process inspection. Prefer `.env` with restrictive "
            "permissions or the hidden prompt when possible.\n"
        )
    readme = (
        "# extract-amr single-file bundle\n"
        "\n"
        "Generated by `scripts/build_single_file.py`. The bundle embeds the full\n"
        "extract_amr package (CLI + API) in one file; run it with venv Python\n"
        "that already provides Click and Scapy.\n\n"
        "In the examples below, the python path is `/usr/local/ipcs/peon/venv/bin/python3`.\n"
        "Replace it with your venv Python path.\n"
        f"{passphrase_notes}"
        "\n"
        "## Inspect a packet capture to generate AMR or AMR-WB reports\n"
        "\n"
        "```console\n"
        f"{python} extract-amr.py inspect call.pcapng --progress\n"
        "```\n"
        "\n"
        "## Extract an AMR flow using a selector from the reports\n"
        "\n"
        "```console\n"
        f"{python} extract-amr.py extract call.pcapng --progress \\\n"
        "   --src-address 192.168.1.1 --dst-address 10.10.10.1 \\\n"
        "   --src-port 4000 --dst-port 5000 --ssrc 1544726223 \\\n"
        "   --payload-type 98 --output call1.amr\n"
        "```\n"
        "\n"
        "## Extract an AMR-WB flow using a selector from the reports\n"
        "\n"
        "```console\n"
        f"{python} extract-amr.py extract call.pcapng --progress \\\n"
        "   --src-address 192.168.1.2 --dst-address 10.10.10.2 \\\n"
        "   --src-port 4002 --dst-port 5002 --ssrc 1544726225 \\\n"
        "   --payload-type 97 --output call2.awb\n"
        "```\n"
        "\n"
        "Use `.amr` extension for AMR-NB and `.awb` for AMR-WB in the output files, \n"
        "then convert them to other audio formats with `ffmpeg` or similar tools \n"
        "that support these input formats. The project folder README.md contains \n"
        "examples on how to convert them to WAV format using `ffmpeg` or `Audacity`."
    )
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    print(f"wrote {readme_path}")


def build(
    output_dir: Path,
    keep_flat: bool,
    shebang: Optional[str],
    with_readme: bool,
    encryption_passphrase: Optional[str] = None,
    validity: Optional[float] = None,
) -> Path:
    print("checking module order and collisions")
    check_order_covers_package()
    check_dependency_order()
    check_name_collisions()

    print("assembling flat source")
    flat_source = assemble_flat_source(validity)
    compile(flat_source, "<flat-bundle>", "exec")

    output_dir.mkdir(parents=True, exist_ok=True)
    if keep_flat:
        flat_path = output_dir / FLAT_NAME
        flat_path.write_text(flat_source, encoding="utf-8")
        print(f"wrote {flat_path}")

    launcher = wrap_launcher(flat_source, shebang, encryption_passphrase)
    compile(launcher, "<launcher>", "exec")
    bundle_path = output_dir / BUNDLE_NAME
    bundle_path.write_text(launcher, encoding="utf-8")
    print(f"wrote {bundle_path}")
    if with_readme:
        emit_readme(output_dir, shebang, encryption_passphrase is not None)
    return bundle_path


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "dist",
        help="directory for generated artifacts (default: dist)",
    )
    parser.add_argument(
        "--keep-flat",
        action="store_true",
        help="also write the readable uncompressed flat source",
    )
    parser.add_argument(
        "--shebang",
        default=None,
        help="interpreter path to bake into the first line",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the post-build smoke verification",
    )
    parser.add_argument(
        "--with-readme",
        action="store_true",
        help="also write README.md deployment notes",
    )
    parser.add_argument(
        "--enc-passphrase",
        default=None,
        help="printable passphrase used to encrypt the embedded script",
    )
    parser.add_argument(
        "--valid-days",
        type=positive_int,
        default=None,
        help="positive number of days before the generated script expires",
    )
    arguments = parser.parse_args(argv)

    try:
        if arguments.enc_passphrase is not None:
            normalize_passphrase(arguments.enc_passphrase)
        validity = (
            time.time() + arguments.valid_days * 86400 if arguments.valid_days is not None else None
        )
        bundle_path = build(
            arguments.output_dir,
            arguments.keep_flat,
            arguments.shebang,
            arguments.with_readme,
            arguments.enc_passphrase,
            validity,
        )
        if not arguments.no_verify:
            smoke_verify(bundle_path, arguments.enc_passphrase)

        rebuild = build(
            arguments.output_dir / ".determinism",
            False,
            arguments.shebang,
            False,
            arguments.enc_passphrase,
            validity,
        )
        if arguments.enc_passphrase is None and digest(bundle_path) != digest(rebuild):
            raise BuildError("build is not deterministic")
        rebuild.unlink()
        shutil.rmtree(rebuild.parent)

        kib = bundle_path.stat().st_size / 1024.0
        if arguments.enc_passphrase is None:
            print(f"determinism: identical across rebuilds ({digest(bundle_path)[:12]})")
        else:
            print("determinism: skipped for randomized Fernet ciphertext")
        print(f"done: {bundle_path} ({kib:.1f} KiB)")
        return 0
    except BuildError as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
