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
import shutil
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO_ROOT / "extract_amr"

MODULE_ORDER = [
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
            targets.extend(alias.name.split(".")[0] for alias in node.names)
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


def assemble_flat_source() -> str:
    header = [
        '"""extract-amr single-file flat source (generated).',
        "",
        "Concatenation of the extract_amr package in dependency order.",
        "Regenerate with scripts/build_single_file.py --keep-flat.",
        '"""',
        "from __future__ import annotations",
        f'__version__ = "{read_version()}"',
    ]
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
    chunks.append('if __name__ == "__main__":\n    cli()')
    return "\n\n\n".join(chunks) + "\n"


def wrap_launcher(flat_source: str, shebang: Optional[str]) -> str:
    blob = base64.encodebytes(zlib.compress(flat_source.encode("utf-8"), 9))
    blob_lines = blob.decode("ascii").splitlines()
    lines: List[str] = []
    if shebang:
        lines.append(f"#!{shebang}")
    lines.extend(
        [
            '"""extract-amr single-file bundle (generated; do not edit).',
            "",
            "The flat extract-amr source is zlib-compressed and base64-encoded",
            "below. Regenerate with scripts/build_single_file.py.",
            '"""',
            "import base64",
            "import traceback",
            "import zlib",
            "",
            "",
            'COMPRESSED_SCRIPT = """\\',
        ]
    )
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
            "",
            "",
            'if __name__ == "__main__":',
            "    script_content = unwrap_and_decompress(COMPRESSED_SCRIPT)",
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


def run_command(command: List[str], label: str) -> None:
    result = subprocess.run(
        command,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stderr.decode(errors="replace"))
        raise BuildError(f"{label} failed with exit code {result.returncode}")


def smoke_verify(bundle_path: Path) -> None:
    print("smoke: --help")
    run_command([sys.executable, str(bundle_path), "--help"], "--help smoke")

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
                str(bundle_path),
                "extract",
                str(capture_path),
                *selector_arguments,
                "--output",
                str(bundled),
            ],
            f"bundle extraction for {capture}",
        )
        if reference.read_bytes() != bundled.read_bytes():
            raise BuildError(f"bundle output differs for {capture}")
        reference.unlink()
        bundled.unlink()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def emit_readme(output_dir: Path, shebang: Optional[str]) -> None:
    python = shebang or "python3"
    readme = (
        "# extract-amr single-file bundle\n"
        "\n"
        "Generated by `scripts/build_single_file.py`. The bundle embeds the full\n"
        "extract_amr package (CLI + API) in one file; run it with venv Python\n"
        "that already provides Click and Scapy.\n\n"
        "In the examples below, the python path is `/usr/local/ipcs/peon/venv/bin/python3`.\n"
        "Replace it with your venv Python path.\n"
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
        "examples on how to convert them to WAV format using `ffmpeg`."
    )
    readme_path = output_dir / "README.md"
    readme_path.write_text(readme, encoding="utf-8")
    print(f"wrote {readme_path}")


def build(
    output_dir: Path,
    keep_flat: bool,
    shebang: Optional[str],
    with_readme: bool,
) -> Path:
    print("checking module order and collisions")
    check_order_covers_package()
    check_dependency_order()
    check_name_collisions()

    print("assembling flat source")
    flat_source = assemble_flat_source()
    compile(flat_source, "<flat-bundle>", "exec")

    output_dir.mkdir(parents=True, exist_ok=True)
    if keep_flat:
        flat_path = output_dir / FLAT_NAME
        flat_path.write_text(flat_source, encoding="utf-8")
        print(f"wrote {flat_path}")

    launcher = wrap_launcher(flat_source, shebang)
    compile(launcher, "<launcher>", "exec")
    bundle_path = output_dir / BUNDLE_NAME
    bundle_path.write_text(launcher, encoding="utf-8")
    print(f"wrote {bundle_path}")
    if with_readme:
        emit_readme(output_dir, shebang)
    return bundle_path


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
    arguments = parser.parse_args(argv)

    try:
        bundle_path = build(
            arguments.output_dir,
            arguments.keep_flat,
            arguments.shebang,
            arguments.with_readme,
        )
        if not arguments.no_verify:
            smoke_verify(bundle_path)

        rebuild = build(
            arguments.output_dir / ".determinism",
            False,
            arguments.shebang,
            False,
        )
        if digest(bundle_path) != digest(rebuild):
            raise BuildError("build is not deterministic")
        rebuild.unlink()
        shutil.rmtree(rebuild.parent)

        kib = bundle_path.stat().st_size / 1024.0
        print(f"determinism: identical across rebuilds ({digest(bundle_path)[:12]})")
        print(f"done: {bundle_path} ({kib:.1f} KiB)")
        return 0
    except BuildError as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
