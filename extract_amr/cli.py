"""Click command-line contract for capture inspection and extraction."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Set, Tuple, Type, TypeVar

import click

from .api import _extraction_pass_count, extract_flows, extract_pcap, inspect_pcap
from .bits import BIT_BACKEND
from .capture import CaptureProgress
from .errors import AmbiguousSelectionError, ExtractAmrError, ProgressError
from .models import (
    Codec,
    ExtractionReport,
    ExtractOptions,
    FlowCandidate,
    FlowKey,
    FlowSelector,
    GapPolicy,
    InspectOptions,
    MalformedPolicy,
    PayloadMode,
    ResourceLimits,
    SelectedFlow,
)

EnumType = TypeVar("EnumType", Codec, PayloadMode, GapPolicy, MalformedPolicy)


def _enum_value(enum_type: Type[EnumType], value: Optional[str]) -> Optional[EnumType]:
    if value is None:
        return None
    return enum_type(value)


def _selector(
    src_address: Optional[str],
    dst_address: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    ssrc: Optional[int],
    payload_type: Optional[int],
) -> FlowSelector:
    return FlowSelector(
        src_address=src_address,
        dst_address=dst_address,
        src_port=src_port,
        dst_port=dst_port,
        ssrc=ssrc,
        payload_type=payload_type,
    )


def _limits(
    max_candidates: int,
    max_samples_per_flow: int,
    max_diagnostics: int,
    reorder_window: int,
) -> ResourceLimits:
    return ResourceLimits(
        max_candidates=max_candidates,
        max_samples_per_flow=max_samples_per_flow,
        max_diagnostics=max_diagnostics,
        reorder_window=reorder_window,
    )


def _usage_error(error: ValueError) -> click.UsageError:
    return click.UsageError(str(error))


def _selector_text(
    flow_key: FlowKey,
    codec: Optional[Codec] = None,
    payload_mode: Optional[PayloadMode] = None,
) -> str:
    values = [
        ("--src-address", flow_key.src_address),
        ("--dst-address", flow_key.dst_address),
        ("--src-port", flow_key.src_port),
        ("--dst-port", flow_key.dst_port),
        ("--ssrc", flow_key.ssrc),
        ("--payload-type", flow_key.payload_type),
    ]
    if codec is not None:
        values.append(("--codec", codec.value))
    if payload_mode is not None:
        values.append(("--mode", payload_mode.value))
    return " ".join(f"{option} {value}" for option, value in values)


def _candidate_formats(
    candidate: FlowCandidate,
    codec: Optional[Codec],
    payload_mode: Optional[PayloadMode],
) -> List[str]:
    return [
        (f"{evidence.codec.value}/{evidence.payload_mode.value} samples={evidence.success_count}")
        for evidence in candidate.valid_formats
        if (codec is None or evidence.codec is codec)
        and (payload_mode is None or evidence.payload_mode is payload_mode)
    ]


def _render_inspection(options: InspectOptions, report) -> None:
    click.echo(
        "capture: "
        f"packets={report.capture_packet_count} udp={report.udp_packet_count} "
        f"rtp={report.rtp_packet_count} malformed-rtp={report.malformed_rtp_count}",
    )
    backend = f"bit-backend: {BIT_BACKEND.name}"
    if BIT_BACKEND.fallback_reason:
        backend += f" (fallback: {BIT_BACKEND.fallback_reason})"
    click.echo(backend)
    if not report.candidates:
        click.echo("candidates: none")
    for candidate in report.candidates:
        formats = _candidate_formats(candidate, options.codec, options.payload_mode)
        if not formats and not options.report_all:
            continue
        click.echo(f"candidate: {candidate.candidate_id}")
        click.echo(f"  selector: {_selector_text(candidate.flow_key)}")
        click.echo(f"  formats: {', '.join(formats) if formats else 'none'}")
    if not options.progress:
        for diagnostic in report.diagnostics:
            packet = diagnostic.provenance.packet_number
            location = f"packet {packet}" if packet is not None else "unknown packet"
            click.echo(f"diagnostic: {location}: {diagnostic.reason}: {diagnostic.message}")
        if report.diagnostic_overflow_count:
            click.echo(f"diagnostics omitted: {report.diagnostic_overflow_count}")
    discovery = report.discovery
    if discovery.candidate_overflow_count or discovery.sample_overflow_count:
        click.echo(
            "observations omitted: "
            f"candidates={discovery.candidate_overflow_count} "
            f"samples={discovery.sample_overflow_count}",
        )


def _render_error(error: ExtractAmrError) -> str:
    lines = [f"[{error.code}] {error}"]
    if isinstance(error, AmbiguousSelectionError):
        lines.append("candidate selectors:")
        for selection in error.candidates:
            if isinstance(selection, SelectedFlow):
                lines.append(
                    "  "
                    + _selector_text(
                        selection.flow_key,
                        selection.codec,
                        selection.payload_mode,
                    ),
                )
    else:
        available = error.details.get("available_candidates", ())
        selectors = []
        for fields in available:
            if not isinstance(fields, dict):
                continue
            try:
                flow_key = FlowKey(
                    src_address=fields["src_address"],
                    dst_address=fields["dst_address"],
                    src_port=fields["src_port"],
                    dst_port=fields["dst_port"],
                    ssrc=fields["ssrc"],
                    payload_type=fields["payload_type"],
                )
            except (KeyError, TypeError, ValueError):
                continue
            formats = fields.get("formats", ())
            valid_formats = [
                item for item in formats if isinstance(item, dict) and item.get("valid") is True
            ]
            if valid_formats:
                for item in valid_formats:
                    try:
                        selectors.append(
                            _selector_text(
                                flow_key,
                                Codec(item["codec"]),
                                PayloadMode(item["payload_mode"]),
                            ),
                        )
                    except (KeyError, ValueError):
                        continue
            else:
                selectors.append(_selector_text(flow_key))
        if selectors:
            lines.append("available candidate selectors:")
            lines.extend(f"  {selector}" for selector in selectors)
    return "\n".join(lines)


def _is_terminal(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


class _ByteProgressRenderer:
    def __init__(self, bar: Any, total: int) -> None:
        self._bar = bar
        self._pending = 0
        self._threshold = max(1, min(65536, total // 1000 or 1))

    def advance(self, amount: int) -> None:
        self._pending += amount
        if self._pending >= self._threshold:
            self.flush()

    def flush(self) -> None:
        if self._pending:
            amount = self._pending
            self._pending = 0
            try:
                self._bar.update(amount)
            except Exception as error:
                raise ProgressError("unable to render capture progress") from error


@contextmanager
def _capture_progress(
    path: Path,
    pass_count: int,
    enabled: bool,
) -> Iterator[Optional[CaptureProgress]]:
    if not enabled:
        yield None
        return

    renderer: Optional[_ByteProgressRenderer] = None

    def advance(amount: int) -> None:
        if renderer is not None:
            renderer.advance(amount)

    progress = CaptureProgress(path, pass_count, advance)
    standard_error = click.get_text_stream("stderr")
    if not _is_terminal(standard_error):
        yield progress
        progress.ensure_complete()
        return

    try:
        with click.progressbar(
            length=progress.total_bytes,
            label="Processing capture",
            file=standard_error,
            show_eta=True,
            show_percent=True,
        ) as bar:
            renderer = _ByteProgressRenderer(bar, progress.total_bytes)
            try:
                yield progress
                progress.ensure_complete()
            finally:
                renderer.flush()
    except ExtractAmrError:
        raise
    except Exception as error:
        raise ProgressError("unable to render capture progress") from error


def _run_inspect(options: InspectOptions) -> None:
    """Inspect a capture through the public API and render its report."""

    try:
        with _capture_progress(options.input_path, 1, options.progress) as progress:
            report = inspect_pcap(
                options.input_path,
                selector=options.selector,
                limits=options.limits,
                _progress=progress,
            )
        _render_inspection(options, report)
    except ExtractAmrError as error:
        raise click.ClickException(_render_error(error)) from error


def _safe_address(address: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9.-]+", "-", address).strip(".-")
    return sanitized or "address"


def _flow_filename(selection: SelectedFlow) -> str:
    key = selection.flow_key
    identity = "|".join(
        (
            key.src_address,
            str(key.src_port),
            key.dst_address,
            str(key.dst_port),
            str(key.payload_type),
            str(key.ssrc),
        ),
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    extension = ".amr" if selection.codec is Codec.AMR else ".awb"
    return (
        f"src-{_safe_address(key.src_address)}-{key.src_port}__"
        f"dst-{_safe_address(key.dst_address)}-{key.dst_port}__"
        f"pt-{key.payload_type}__ssrc-{key.ssrc:08x}__{digest}{extension}"
    )


@dataclass
class _StagedFile:
    final_path: Path
    temporary_path: Path
    stream: BinaryIO


class _OutputTransaction:
    def __init__(self) -> None:
        self._files: List[_StagedFile] = []
        self._final_paths: Set[Path] = set()
        self._backups: List[Tuple[Path, Path]] = []
        self._installed_paths: Set[Path] = set()
        self._committed = False

    def __enter__(self) -> "_OutputTransaction":
        return self

    def open(self, final_path: Path) -> BinaryIO:
        final_path = final_path.absolute()
        if final_path in self._final_paths:
            raise OSError(f"duplicate output path: {final_path}")
        if not final_path.parent.is_dir():
            raise OSError(f"output directory does not exist: {final_path.parent}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{final_path.name}.",
            suffix=".tmp",
            dir=str(final_path.parent),
        )
        try:
            stream = os.fdopen(descriptor, "wb")
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass
            raise
        self._files.append(
            _StagedFile(
                final_path=final_path,
                temporary_path=Path(temporary_name),
                stream=stream,
            ),
        )
        self._final_paths.add(final_path)
        return stream

    def commit(self) -> None:
        for staged in self._files:
            staged.stream.flush()
            os.fsync(staged.stream.fileno())
            staged.stream.close()
        try:
            for staged in self._files:
                if not os.path.lexists(str(staged.final_path)):
                    continue
                descriptor, backup_name = tempfile.mkstemp(
                    prefix=f".{staged.final_path.name}.",
                    suffix=".backup",
                    dir=str(staged.final_path.parent),
                )
                os.close(descriptor)
                backup_path = Path(backup_name)
                try:
                    os.replace(str(staged.final_path), str(backup_path))
                except OSError:
                    try:
                        backup_path.unlink()
                    except OSError:
                        pass
                    raise
                self._backups.append((staged.final_path, backup_path))
            for staged in self._files:
                os.replace(str(staged.temporary_path), str(staged.final_path))
                self._installed_paths.add(staged.final_path)
        except OSError as error:
            rollback_errors = self._rollback()
            if rollback_errors:
                raise OSError(
                    "output commit failed and prior outputs could not be fully restored",
                ) from error
            raise
        self._committed = True
        for _, backup_path in self._backups:
            try:
                backup_path.unlink()
            except FileNotFoundError:
                pass

    def _rollback(self) -> List[OSError]:
        errors = []
        backed_up_paths = {final_path for final_path, _ in self._backups}
        for final_path in self._installed_paths - backed_up_paths:
            try:
                final_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                errors.append(error)
        for final_path, backup_path in reversed(self._backups):
            try:
                os.replace(str(backup_path), str(final_path))
            except OSError as error:
                errors.append(error)
        return errors

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        del exc_type, exc_value, traceback
        cleanup_errors = []
        for staged in self._files:
            if not staged.stream.closed:
                try:
                    staged.stream.close()
                except OSError as error:
                    cleanup_errors.append(error)
            if not self._committed:
                try:
                    staged.temporary_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    cleanup_errors.append(error)
        if self._committed:
            for _, backup_path in self._backups:
                try:
                    backup_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    cleanup_errors.append(error)
        if cleanup_errors:
            raise OSError("failed to remove one or more staged output files") from cleanup_errors[0]


def _same_path(first: Path, second: Path) -> bool:
    try:
        return os.path.samefile(str(first), str(second))
    except OSError:
        return first.resolve() == second.resolve()


def _render_extraction(report: ExtractionReport, show_diagnostics: bool = True) -> None:
    selection = report.selected_flow
    click.echo(f"output: {report.output_path}")
    click.echo(
        "flow: "
        + _selector_text(
            selection.flow_key,
            selection.codec,
            selection.payload_mode,
        ),
    )
    backend = f"bit-backend: {report.bit_backend}"
    if report.bit_backend_fallback_reason:
        backend += f" (fallback: {report.bit_backend_fallback_reason})"
    click.echo(backend)
    click.echo(
        "packets: "
        f"capture={report.capture_packet_count} udp={report.udp_packet_count} "
        f"selected-rtp={report.selected_rtp_packet_count} passes={report.capture_pass_count}",
    )
    click.echo(
        "frames: "
        f"emitted={report.emitted_frame_count} bad-quality={report.bad_quality_frame_count} "
        f"gaps={report.gap_count} inserted-no-data={report.inserted_no_data_count}",
    )
    click.echo(
        "events: "
        f"duplicates={report.duplicate_packet_count} "
        f"reordered={report.reordered_packet_count} late={report.late_packet_count} "
        f"overlap={report.overlap_frame_count} malformed={report.malformed_packet_count} "
        f"history-overflow={report.packet_history_overflow_count}",
    )
    if show_diagnostics:
        for diagnostic in report.diagnostics:
            packet = diagnostic.provenance.packet_number
            location = f"packet {packet}" if packet is not None else "unknown packet"
            click.echo(f"diagnostic: {location}: {diagnostic.reason}: {diagnostic.message}")
        if report.diagnostic_overflow_count:
            click.echo(f"diagnostics omitted: {report.diagnostic_overflow_count}")


def _single_extract(
    options: ExtractOptions,
    progress: Optional[CaptureProgress],
    transaction: _OutputTransaction,
) -> ExtractionReport:
    output_path = options.output_path
    if output_path is None:
        raise ValueError("single-flow extraction requires output_path")
    if _same_path(options.input_path, output_path):
        raise OSError("input and output paths must be different")
    output = transaction.open(output_path)
    report = extract_pcap(
        options.input_path,
        output,
        selector=options.selector,
        codec=options.codec,
        payload_mode=options.payload_mode,
        gap_policy=options.gap_policy,
        malformed_policy=options.malformed_policy,
        limits=options.limits,
        _progress=progress,
    )
    return replace(report, output_path=output_path.absolute())


def _multi_extract(
    options: ExtractOptions,
    progress: Optional[CaptureProgress],
    transaction: _OutputTransaction,
) -> Tuple[ExtractionReport, ...]:
    output_dir = options.output_dir
    if output_dir is None:
        raise ValueError("multi-flow extraction requires output_dir")
    output_dir.mkdir(parents=True, exist_ok=True)
    if not output_dir.is_dir():
        raise OSError(f"output directory is not a directory: {output_dir}")
    paths: Dict[FlowKey, Path] = {}

    def output_for(selection: SelectedFlow) -> BinaryIO:
        final_path = output_dir / _flow_filename(selection)
        if _same_path(options.input_path, final_path):
            raise OSError("input and output paths must be different")
        paths[selection.flow_key] = final_path.absolute()
        return transaction.open(final_path)

    reports = extract_flows(
        options.input_path,
        output_for,
        selector=options.selector,
        codec=options.codec,
        payload_mode=options.payload_mode,
        gap_policy=options.gap_policy,
        malformed_policy=options.malformed_policy,
        limits=options.limits,
        _progress=progress,
    )
    completed = tuple(
        replace(report, output_path=paths[report.selected_flow.flow_key]) for report in reports
    )
    return tuple(sorted(completed, key=lambda item: str(item.output_path)))


def _run_extract(options: ExtractOptions) -> None:
    """Extract through the public API with transactional path output."""

    try:
        pass_count = _extraction_pass_count(
            options.selector,
            options.codec,
            options.payload_mode,
        )
        with _OutputTransaction() as transaction:
            with _capture_progress(options.input_path, pass_count, options.progress) as progress:
                if options.output_dir is not None:
                    reports = _multi_extract(options, progress, transaction)
                else:
                    reports = (_single_extract(options, progress, transaction),)
            transaction.commit()
        for report in reports:
            _render_extraction(report, show_diagnostics=not options.progress)
    except ExtractAmrError as error:
        raise click.ClickException(_render_error(error)) from error
    except (OSError, ValueError) as error:
        raise click.ClickException(str(error)) from error


def _common_options(command):
    options = [
        click.option("--src-address", help="Source IP address."),
        click.option("--dst-address", help="Destination IP address."),
        click.option("--src-port", type=click.IntRange(1, 65535), help="Source UDP port."),
        click.option("--dst-port", type=click.IntRange(1, 65535), help="Destination UDP port."),
        click.option("--ssrc", type=click.IntRange(0, 0xFFFFFFFF), help="RTP SSRC."),
        click.option("--payload-type", type=click.IntRange(0, 127), help="RTP payload type."),
        click.option(
            "--codec",
            type=click.Choice([item.value for item in Codec], case_sensitive=False),
        ),
        click.option(
            "--mode",
            type=click.Choice([item.value for item in PayloadMode], case_sensitive=False),
        ),
        click.option(
            "--max-candidates",
            type=click.IntRange(min=1),
            default=1024,
            show_default=True,
        ),
        click.option(
            "--max-samples-per-flow",
            type=click.IntRange(min=1),
            default=64,
            show_default=True,
        ),
        click.option(
            "--max-diagnostics",
            type=click.IntRange(1, 100),
            default=1,
            show_default=True,
        ),
        click.option(
            "--progress",
            is_flag=True,
            help="Show progress bar and disable diagnostics.",
        ),
        click.option(
            "--reorder-window",
            type=click.IntRange(min=1),
            default=64,
            show_default=True),
    ]
    for option in reversed(options):
        command = option(command)
    return command


@click.group()
def cli() -> None:
    """Inspect packet capture and extract AMR or AMR-WB media."""


@cli.command("inspect")
@click.argument(
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@_common_options
@click.option(
    "--report-all",
    is_flag=True,
    help="Show all RTP reports."
)
@click.pass_context
def inspect_command(
    context: click.Context,
    input_path: Path,
    src_address: Optional[str],
    dst_address: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    ssrc: Optional[int],
    payload_type: Optional[int],
    codec: Optional[str],
    mode: Optional[str],
    max_candidates: int,
    max_samples_per_flow: int,
    max_diagnostics: int,
    progress: bool,
    reorder_window: int,
    report_all: bool,
) -> InspectOptions:
    """
    Inspect packet capture and generate media reports.

    Validates options and processes the INPUT_PATH PCAP file to identify
    RTP streams matching the provided filters.
    """

    if progress and (
        context.get_parameter_source("max_diagnostics") is click.core.ParameterSource.COMMANDLINE
    ):
        raise click.UsageError("--progress and --max-diagnostics are mutually exclusive")
    options = InspectOptions(
        input_path=input_path,
        selector=_selector(
            src_address,
            dst_address,
            src_port,
            dst_port,
            ssrc,
            payload_type,
        ),
        codec=_enum_value(Codec, codec),
        payload_mode=_enum_value(PayloadMode, mode),
        limits=_limits(
            max_candidates,
            max_samples_per_flow,
            0 if progress else max_diagnostics,
            reorder_window,
        ),
        progress=progress,
        report_all=report_all,
    )
    _run_inspect(options)
    return options


@cli.command("extract")
@click.argument(
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=Path))
@click.option(
    "--gap-policy",
    type=click.Choice([item.value for item in GapPolicy], case_sensitive=False),
    default=GapPolicy.OMIT.value,
    show_default=True,
)
@click.option(
    "--malformed-policy",
    type=click.Choice([item.value for item in MalformedPolicy], case_sensitive=False),
    default=MalformedPolicy.SKIP.value,
    show_default=True,
)
@_common_options
@click.pass_context
def extract_command(
    context: click.Context,
    input_path: Path,
    output: Optional[Path],
    output_dir: Optional[Path],
    gap_policy: str,
    malformed_policy: str,
    src_address: Optional[str],
    dst_address: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    ssrc: Optional[int],
    payload_type: Optional[int],
    codec: Optional[str],
    mode: Optional[str],
    max_candidates: int,
    max_samples_per_flow: int,
    max_diagnostics: int,
    progress: bool,
    reorder_window: int,
) -> ExtractOptions:
    """
    Process packet captures and extract AMR or AMR-WB media.
    
    Validate options for extracting media from INPUT_PATH.
    """

    try:
        if progress and (
            context.get_parameter_source("max_diagnostics")
            is click.core.ParameterSource.COMMANDLINE
        ):
            raise click.UsageError(
                "--progress and --max-diagnostics are mutually exclusive",
            )
        options = ExtractOptions(
            input_path=input_path,
            output_path=output,
            output_dir=output_dir,
            selector=_selector(
                src_address,
                dst_address,
                src_port,
                dst_port,
                ssrc,
                payload_type,
            ),
            codec=_enum_value(Codec, codec),
            payload_mode=_enum_value(PayloadMode, mode),
            gap_policy=GapPolicy(gap_policy),
            malformed_policy=MalformedPolicy(malformed_policy),
            limits=_limits(
                max_candidates,
                max_samples_per_flow,
                0 if progress else max_diagnostics,
                reorder_window,
            ),
            progress=progress,
        )
    except ValueError as error:
        raise _usage_error(error) from error
    _run_extract(options)
    return options
