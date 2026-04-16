#!/usr/bin/env python3
"""
NullTrace TUI — Terminal User Interface
Multi-carrier steganography toolkit with splash screen and full interactive workflow.
"""

import asyncio
import os
import threading
from pathlib import Path

from textual.app        import App, ComposeResult
from textual.screen     import Screen
from textual.binding    import Binding
from textual.widgets    import (
    Button, DataTable, Footer, Header, Input, Label,
    Log, Select, Static, Switch, TabbedContent, TabPane,
)
from textual.containers import Center, Container, Horizontal, ScrollableContainer, Vertical
from textual            import on, work
from textual.color      import Color


# ─────────────────────────────────────────────────────────────────────────────
#  ASCII ART
# ─────────────────────────────────────────────────────────────────────────────

BANNER = """\
 ███╗   ██╗██╗   ██╗██╗     ██╗      ████████╗██████╗  █████╗  ██████╗███████╗
 ████╗  ██║██║   ██║██║     ██║         ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
 ██╔██╗ ██║██║   ██║██║     ██║         ██║   ██████╔╝███████║██║     █████╗
 ██║╚██╗██║██║   ██║██║     ██║         ██║   ██╔══██╗██╔══██║██║     ██╔══╝
 ██║ ╚████║╚██████╔╝███████╗███████╗    ██║   ██║  ██║██║  ██║╚██████╗███████╗
 ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝"""

TAGLINE  = "Multi-carrier steganography toolkit"
SUBLINE  = "Leave no fingerprints."
VERSION  = "v1.0.0"

METHOD_OPTIONS = [
    ("auto  — detect from file extension",  "auto"),
    ("lsb   — PNG/BMP/TIFF pixel LSB",      "lsb"),
    ("exif  — JPEG EXIF UserComment",        "exif"),
    ("wav   — WAV audio sample LSB",         "wav"),
    ("eof   — Append after EOF marker",      "eof"),
    ("zwc   — Zero-width Unicode chars",     "zwc"),
    ("zip   — ZIP comment field",            "zip"),
    ("pdf   — PDF XMP metadata",             "pdf"),
    ("ads   — NTFS Alternate Data Stream",   "ads"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  SPLASH SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class SplashScreen(Screen):
    """Full-screen animated splash. Dismisses on keypress or after 3s."""

    DEFAULT_CSS = """
    SplashScreen {
        background: #0a0a0a;
        align: center middle;
    }
    #splash-box {
        width: auto;
        height: auto;
        padding: 2 4;
        border: double #00ff41;
        background: #0a0a0a;
        align: center middle;
    }
    #banner {
        color: #00ff41;
        text-style: bold;
        content-align: center middle;
        width: auto;
    }
    #tagline {
        color: #aaffaa;
        content-align: center middle;
        width: 100%;
        margin-top: 1;
    }
    #subline {
        color: #44aa44;
        content-align: center middle;
        width: 100%;
        text-style: italic;
    }
    #version-label {
        color: #336633;
        content-align: center middle;
        width: 100%;
        margin-top: 1;
    }
    #prompt-label {
        color: #00ff41;
        content-align: center middle;
        width: 100%;
        margin-top: 2;
        text-style: bold blink;
    }
    """

    BINDINGS = [Binding("*", "dismiss_splash", show=False)]

    def compose(self) -> ComposeResult:
        with Center():
            with Vertical(id="splash-box"):
                yield Static(BANNER,            id="banner")
                yield Static(TAGLINE,           id="tagline")
                yield Static(SUBLINE,           id="subline")
                yield Static(VERSION,           id="version-label")
                yield Static("[ Press any key ]", id="prompt-label")

    def on_mount(self) -> None:
        # Auto-dismiss after 4 seconds
        self.set_timer(4.0, self.action_dismiss_splash)

    def action_dismiss_splash(self) -> None:
        self.app.push_screen(MainMenuScreen())

    def on_key(self, event) -> None:
        self.action_dismiss_splash()

    def on_click(self, event) -> None:
        self.action_dismiss_splash()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN MENU SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class MainMenuScreen(Screen):
    """Three-button main navigation."""

    DEFAULT_CSS = """
    MainMenuScreen {
        background: #0a0a0a;
    }
    #menu-title {
        color: #00ff41;
        text-style: bold;
        content-align: center middle;
        width: 100%;
        padding: 1 0;
    }
    #menu-subtitle {
        color: #336633;
        content-align: center middle;
        width: 100%;
        margin-bottom: 1;
    }
    #menu-container {
        align: center middle;
        height: 1fr;
        width: 100%;
    }
    #menu-buttons {
        width: 72;
        height: auto;
        align: center middle;
    }
    .menu-card {
        width: 100%;
        height: 7;
        border: solid #1a4a1a;
        background: #0d1a0d;
        margin-bottom: 1;
        padding: 1 2;
    }
    .menu-card:hover {
        border: solid #00ff41;
        background: #0d2a0d;
    }
    .card-title {
        color: #00ff41;
        text-style: bold;
        width: 100%;
    }
    .card-desc {
        color: #557755;
        width: 100%;
        margin-top: 0;
    }
    .card-key {
        color: #224422;
        width: 100%;
        margin-top: 1;
        text-style: italic;
    }
    Button.menu-btn {
        width: 100%;
        height: 7;
        border: solid #1a4a1a;
        background: #0d1a0d;
        margin-bottom: 1;
        color: #00ff41;
    }
    Button.menu-btn:hover {
        border: solid #00ff41;
        background: #0d2a0d;
    }
    Button.menu-btn:focus {
        border: solid #00ff41;
    }
    #menu-footer {
        color: #224422;
        content-align: center middle;
        width: 100%;
        padding: 1 0;
    }
    """

    BINDINGS = [
        Binding("h", "go_hide",    "Hide",    show=True),
        Binding("e", "go_extract", "Extract", show=True),
        Binding("s", "go_scan",    "Scan",    show=True),
        Binding("q", "quit",       "Quit",    show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("NULLTRACE", id="menu-title")
        yield Static(f"{TAGLINE}  ·  {VERSION}", id="menu-subtitle")
        with Center(id="menu-container"):
            with Vertical(id="menu-buttons"):
                yield Button(
                    "[ H ]  HIDE\n       Embed encrypted data into a carrier file.\n       PNG · JPEG · WAV · ZIP · PDF · TXT · ADS",
                    id="btn-hide", classes="menu-btn", variant="default"
                )
                yield Button(
                    "[ E ]  EXTRACT\n       Pull hidden data from a carrier file.\n       Decrypts with AES-256-GCM",
                    id="btn-extract", classes="menu-btn", variant="default"
                )
                yield Button(
                    "[ S ]  SCAN\n       Blind-scan for steganographic content.\n       Statistical · Signatures · EOF · ADS · ZWC",
                    id="btn-scan", classes="menu-btn", variant="default"
                )
        yield Static("NullTrace  ·  Leave no fingerprints.", id="menu-footer")
        yield Footer()

    @on(Button.Pressed, "#btn-hide")
    def go_hide(self): self.app.push_screen(HideScreen())

    @on(Button.Pressed, "#btn-extract")
    def go_extract(self): self.app.push_screen(ExtractScreen())

    @on(Button.Pressed, "#btn-scan")
    def go_scan(self): self.app.push_screen(ScanScreen())

    def action_go_hide(self):    self.app.push_screen(HideScreen())
    def action_go_extract(self): self.app.push_screen(ExtractScreen())
    def action_go_scan(self):    self.app.push_screen(ScanScreen())
    def action_quit(self):       self.app.exit()


# ─────────────────────────────────────────────────────────────────────────────
#  SHARED STYLES
# ─────────────────────────────────────────────────────────────────────────────

FORM_CSS = """
    .op-screen {
        background: #0a0a0a;
    }
    .screen-title {
        color: #00ff41;
        text-style: bold;
        content-align: left middle;
        width: 100%;
        padding: 0 2;
        height: 3;
        border-bottom: solid #1a3a1a;
    }
    .form-area {
        width: 60;
        height: auto;
        padding: 1 2;
    }
    .field-label {
        color: #557755;
        width: 100%;
        margin-top: 1;
        text-style: bold;
    }
    Input {
        background: #0d1a0d;
        border: solid #224422;
        color: #aaffaa;
        width: 100%;
    }
    Input:focus {
        border: solid #00ff41;
    }
    Select {
        background: #0d1a0d;
        border: solid #224422;
        color: #aaffaa;
        width: 100%;
    }
    Select:focus {
        border: solid #00ff41;
    }
    .toggle-row {
        height: 3;
        margin-top: 1;
        width: 100%;
    }
    Switch {
        margin: 0 1;
    }
    .switch-label {
        color: #557755;
        width: 1fr;
        content-align: left middle;
    }
    .action-btn {
        margin-top: 2;
        width: 100%;
        background: #0d2a0d;
        color: #00ff41;
        border: solid #00ff41;
        text-style: bold;
    }
    .action-btn:hover {
        background: #1a4a1a;
    }
    .back-btn {
        margin-top: 1;
        width: 100%;
        background: #0a0a0a;
        color: #335533;
        border: solid #224422;
    }
    .back-btn:hover {
        color: #557755;
        border: solid #335533;
    }
    .output-panel {
        height: 1fr;
        border: solid #1a3a1a;
        background: #030a03;
        margin: 1 2;
    }
    Log {
        background: #030a03;
        color: #aaffaa;
        height: 100%;
    }
    .layout-row {
        height: 1fr;
        width: 100%;
    }
"""


# ─────────────────────────────────────────────────────────────────────────────
#  HIDE SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class HideScreen(Screen):
    """Embed encrypted payload into a carrier file."""

    DEFAULT_CSS = FORM_CSS + """
    HideScreen {
        background: #0a0a0a;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+r", "run",  "Run",  show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("  ▶  HIDE  —  Embed encrypted data into a carrier file",
                     classes="screen-title")
        with Horizontal(classes="layout-row"):
            with ScrollableContainer(classes="form-area"):
                yield Label("Carrier file (input)",    classes="field-label")
                yield Input(placeholder="/path/to/carrier.png",
                            id="hide-input",  type="text")

                yield Label("Output file",              classes="field-label")
                yield Input(placeholder="/path/to/output.png",
                            id="hide-output", type="text")

                yield Label("Method",                   classes="field-label")
                yield Select(METHOD_OPTIONS, value="auto", id="hide-method")

                yield Label("Password",                 classes="field-label")
                yield Input(placeholder="encryption password",
                            id="hide-key", password=True)

                # Message / File toggle
                with Horizontal(classes="toggle-row"):
                    yield Label("Hide a FILE instead of text", classes="switch-label")
                    yield Switch(value=False, id="hide-file-toggle")

                yield Label("Message text",             classes="field-label",
                            id="lbl-msg")
                yield Input(placeholder='Text to hide (e.g. "DEADBEEF")',
                            id="hide-msg", type="text")

                yield Label("Payload file path",        classes="field-label",
                            id="lbl-file", display=False)
                yield Input(placeholder="/path/to/secret.pdf",
                            id="hide-file", type="text", display=False)

                yield Button("[ HIDE ]",   id="btn-run",  classes="action-btn")
                yield Button("[ BACK ]",   id="btn-back", classes="back-btn")

            with Vertical(classes="output-panel"):
                yield Log(id="hide-log", auto_scroll=True)
        yield Footer()

    @on(Switch.Changed, "#hide-file-toggle")
    def toggle_payload_type(self, event: Switch.Changed) -> None:
        use_file = event.value
        self.query_one("#lbl-msg",   Label).display  = not use_file
        self.query_one("#hide-msg",  Input).display  = not use_file
        self.query_one("#lbl-file",  Label).display  = use_file
        self.query_one("#hide-file", Input).display  = use_file

    @on(Button.Pressed, "#btn-run")
    def action_run(self) -> None:
        log = self.query_one("#hide-log", Log)
        log.clear()

        input_file  = self.query_one("#hide-input",  Input).value.strip()
        output_file = self.query_one("#hide-output", Input).value.strip()
        password    = self.query_one("#hide-key",    Input).value.strip()
        method      = str(self.query_one("#hide-method", Select).value)
        use_file    = self.query_one("#hide-file-toggle", Switch).value

        if use_file:
            payload_src = self.query_one("#hide-file", Input).value.strip()
            msg         = None
        else:
            msg         = self.query_one("#hide-msg", Input).value
            payload_src = None

        # Validate
        if not input_file:
            log.write_line("[red]Error:[/red] Carrier file path is required.")
            return
        if not output_file:
            log.write_line("[red]Error:[/red] Output file path is required.")
            return
        if not password:
            log.write_line("[red]Error:[/red] Password is required.")
            return
        if not msg and not payload_src:
            log.write_line("[red]Error:[/red] Provide a message or a payload file.")
            return

        self._run_hide(input_file, output_file, password, method, msg, payload_src)

    @work(thread=True)
    def _run_hide(self, input_file, output_file, password, method, msg, payload_src):
        log = self.query_one("#hide-log", Log)

        def out(text): self.call_from_thread(log.write_line, text)

        try:
            # Assemble payload
            if msg:
                raw = msg.encode('utf-8')
                out(f"Payload: {len(raw)} bytes (text message)")
            else:
                with open(payload_src, 'rb') as f:
                    raw = f.read()
                out(f"Payload: {len(raw)} bytes from {Path(payload_src).name}")

            # Encrypt
            from core.crypto import encrypt
            encrypted = encrypt(raw, password)
            out(f"Encrypted: {len(encrypted)} bytes (AES-256-GCM + scrypt)")

            # Auto-detect method
            if method == "auto":
                suffix = Path(input_file).suffix.lower()
                method_map = {
                    '.png': 'lsb', '.bmp': 'lsb', '.tiff': 'lsb', '.tif': 'lsb',
                    '.jpg': 'exif', '.jpeg': 'exif',
                    '.wav': 'wav',
                    '.zip': 'zip',
                    '.pdf': 'pdf',
                    '.txt': 'zwc', '.html': 'zwc', '.htm': 'zwc',
                    '.md': 'zwc',
                }
                method = method_map.get(suffix, 'eof')
            out(f"Method:    {method.upper()}")

            # Execute
            if method == 'lsb':
                from core.lsb import hide, capacity
                cap = capacity(input_file)
                out(f"Capacity:  {cap} bytes available")
                if len(encrypted) > cap:
                    out(f"[red]Error:[/red] Payload too large ({len(encrypted)}B > {cap}B capacity)")
                    return
                hide(input_file, encrypted, password, output_file)

            elif method == 'exif':
                from core.jpeg_exif import hide
                hide(input_file, encrypted, output_file)

            elif method == 'wav':
                from core.wav_lsb import hide
                hide(input_file, encrypted, password, output_file)

            elif method == 'eof':
                from core.eof_append import hide
                hide(input_file, encrypted, output_file)

            elif method == 'zwc':
                from core.zero_width import hide
                with open(input_file, 'r', encoding='utf-8') as f:
                    cover = f.read()
                result = hide(cover, encrypted)
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(result)

            elif method == 'zip':
                from core.zip_comment import hide
                hide(input_file, encrypted, output_file)

            elif method == 'pdf':
                from core.pdf_meta import hide
                hide(input_file, encrypted, output_file)

            elif method == 'ads':
                from core.ntfs_ads import hide
                hide(input_file, output_file, encrypted)
                out(f"[green]Hidden in ADS: {input_file}:{output_file}[/green]")
                out("[green]Host file size is unchanged.[/green]")
                return

            # Report output
            if Path(output_file).exists():
                out(f"[green]Output: {output_file}[/green]")
                out(f"[green]Size:   {os.path.getsize(output_file):,} bytes[/green]")
                out("[bold green]Done — payload hidden successfully.[/bold green]")
            else:
                out("[red]Error: output file was not created.[/red]")

        except Exception as e:
            out(f"[red]Error: {e}[/red]")

    @on(Button.Pressed, "#btn-back")
    def action_back(self): self.app.pop_screen()


# ─────────────────────────────────────────────────────────────────────────────
#  EXTRACT SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class ExtractScreen(Screen):
    """Extract and decrypt a hidden payload from a carrier file."""

    DEFAULT_CSS = FORM_CSS + """
    ExtractScreen {
        background: #0a0a0a;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+r", "run",  "Run",  show=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("  ▶  EXTRACT  —  Pull hidden data from a carrier file",
                     classes="screen-title")
        with Horizontal(classes="layout-row"):
            with ScrollableContainer(classes="form-area"):
                yield Label("Carrier file (input)",  classes="field-label")
                yield Input(placeholder="/path/to/carrier.png",
                            id="ext-input",  type="text")

                yield Label("Method",                classes="field-label")
                yield Select(METHOD_OPTIONS, value="auto", id="ext-method")

                yield Label("Password",              classes="field-label")
                yield Input(placeholder="decryption password",
                            id="ext-key", password=True)

                yield Label("Save to file (optional)", classes="field-label")
                yield Input(placeholder="/path/to/output  (leave blank to display)",
                            id="ext-output", type="text")

                yield Label("ADS stream name (if method = ads)", classes="field-label")
                yield Input(placeholder="stream name",
                            id="ext-stream", type="text")

                yield Button("[ EXTRACT ]", id="btn-run",  classes="action-btn")
                yield Button("[ BACK ]",    id="btn-back", classes="back-btn")

            with Vertical(classes="output-panel"):
                yield Log(id="ext-log", auto_scroll=True)
        yield Footer()

    @on(Button.Pressed, "#btn-run")
    def action_run(self) -> None:
        log = self.query_one("#ext-log", Log)
        log.clear()

        input_file  = self.query_one("#ext-input",  Input).value.strip()
        password    = self.query_one("#ext-key",    Input).value.strip()
        method      = str(self.query_one("#ext-method", Select).value)
        output_file = self.query_one("#ext-output", Input).value.strip() or None
        stream      = self.query_one("#ext-stream", Input).value.strip() or None

        if not input_file:
            log.write_line("[red]Error:[/red] Input file is required.")
            return
        if not password:
            log.write_line("[red]Error:[/red] Password is required.")
            return

        self._run_extract(input_file, password, method, output_file, stream)

    @work(thread=True)
    def _run_extract(self, input_file, password, method, output_file, stream):
        log = self.query_one("#ext-log", Log)
        def out(text): self.call_from_thread(log.write_line, text)

        try:
            suffix = Path(input_file).suffix.lower()

            if method == 'auto':
                method_map = {
                    '.png': 'lsb', '.bmp': 'lsb', '.tiff': 'lsb', '.tif': 'lsb',
                    '.jpg': 'exif', '.jpeg': 'exif',
                    '.wav': 'wav', '.zip': 'zip', '.pdf': 'pdf',
                    '.txt': 'zwc', '.html': 'zwc', '.htm': 'zwc', '.md': 'zwc',
                }
                method = method_map.get(suffix, 'eof')

            out(f"Method: {method.upper()}")
            out("Extracting...")

            if method == 'lsb':
                from core.lsb import extract as x
                raw = x(input_file, password)
            elif method == 'exif':
                from core.jpeg_exif import extract as x
                raw = x(input_file)
            elif method == 'wav':
                from core.wav_lsb import extract as x
                raw = x(input_file, password)
            elif method == 'eof':
                from core.eof_append import extract as x
                raw = x(input_file)
            elif method == 'zwc':
                from core.zero_width import extract as x
                with open(input_file, 'r', encoding='utf-8') as f:
                    raw = x(f.read())
            elif method == 'zip':
                from core.zip_comment import extract as x
                raw = x(input_file)
            elif method == 'pdf':
                from core.pdf_meta import extract as x
                raw = x(input_file)
            elif method == 'ads':
                if not stream:
                    out("[red]Error:[/red] ADS stream name required.")
                    return
                from core.ntfs_ads import extract as x
                raw = x(input_file, stream)
            else:
                out(f"[red]Unknown method: {method}[/red]")
                return

            out(f"Extracted {len(raw)} raw bytes. Decrypting...")

            from core.crypto import decrypt
            plaintext = decrypt(raw, password)

            out(f"[green]Decrypted {len(plaintext)} bytes.[/green]")

            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(plaintext)
                out(f"[green]Saved to: {output_file}[/green]")
            else:
                # Try to display as text
                try:
                    text = plaintext.decode('utf-8')
                    out("")
                    out("─" * 50)
                    out("[bold green]PAYLOAD (text):[/bold green]")
                    out(f"[green]{text}[/green]")
                    out("─" * 50)
                except UnicodeDecodeError:
                    out("")
                    out("─" * 50)
                    out(f"[bold yellow]PAYLOAD (binary {len(plaintext)} bytes):[/bold yellow]")
                    out(plaintext[:128].hex())
                    if len(plaintext) > 128:
                        out(f"  ... ({len(plaintext) - 128} more bytes)")
                    out("─" * 50)

        except Exception as e:
            out(f"[red]Failed: {e}[/red]")

    @on(Button.Pressed, "#btn-back")
    def action_back(self): self.app.pop_screen()


# ─────────────────────────────────────────────────────────────────────────────
#  SCAN SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class ScanScreen(Screen):
    """Blind multi-vector steganography scanner with live streaming results."""

    DEFAULT_CSS = FORM_CSS + """
    ScanScreen {
        background: #0a0a0a;
    }
    #scan-results {
        height: 1fr;
        border: solid #1a3a1a;
        background: #030a03;
        margin: 0 0 0 1;
    }
    DataTable {
        height: 100%;
        background: #030a03;
        color: #aaffaa;
    }
    DataTable > .datatable--header {
        background: #0d2a0d;
        color: #00ff41;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: #1a4a1a;
    }
    #scan-stats {
        height: 3;
        color: #557755;
        content-align: left middle;
        padding: 0 2;
        border-top: solid #1a3a1a;
        background: #0a0a0a;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("ctrl+r", "run",  "Scan", show=True),
    ]

    def __init__(self):
        super().__init__()
        self._scan_count     = 0
        self._suspicious_count = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("  ▶  SCAN  —  Blind steganography detection",
                     classes="screen-title")
        with Horizontal(classes="layout-row"):
            with ScrollableContainer(classes="form-area"):
                yield Label("Target (file or directory)", classes="field-label")
                yield Input(placeholder="/path/to/target  or  /dir/",
                            id="scan-target", type="text")

                yield Label("Password (optional — attempt extraction if found)",
                            classes="field-label")
                yield Input(placeholder="leave blank for detection-only",
                            id="scan-key", password=True)

                yield Label("Extension filter (optional)", classes="field-label")
                yield Input(placeholder=".png,.jpg,.wav  (blank = all)",
                            id="scan-exts", type="text")

                with Horizontal(classes="toggle-row"):
                    yield Label("Recursive directory scan", classes="switch-label")
                    yield Switch(value=False, id="scan-recursive")

                yield Button("[ SCAN ]",  id="btn-run",  classes="action-btn")
                yield Button("[ CLEAR ]", id="btn-clear", classes="back-btn")
                yield Button("[ BACK ]",  id="btn-back", classes="back-btn")

            with Vertical(id="scan-results"):
                yield DataTable(id="scan-table", cursor_type="row")

        yield Static("Ready.", id="scan-stats")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#scan-table", DataTable)
        table.add_columns("Status", "File", "Findings", "Size")

    @on(Button.Pressed, "#btn-run")
    def action_run(self) -> None:
        target    = self.query_one("#scan-target",    Input).value.strip()
        password  = self.query_one("#scan-key",       Input).value.strip() or None
        exts      = self.query_one("#scan-exts",      Input).value.strip()
        recursive = self.query_one("#scan-recursive", Switch).value

        if not target:
            self._add_row("ERR", "—", "Target path is required", "—", suspicious=True)
            return

        ext_filter = None
        if exts:
            ext_filter = {e.strip().lower() for e in exts.split(',') if e.strip()}

        self._scan_count       = 0
        self._suspicious_count = 0
        self._update_stats()
        self._run_scan(target, password, ext_filter, recursive)

    @work(thread=True)
    def _run_scan(self, target, password, ext_filter, recursive):
        from detector.scan import scan_file

        target_path = Path(target)

        if target_path.is_file():
            files = [target_path]
        elif target_path.is_dir():
            pattern = '**/*' if recursive else '*'
            files   = [f for f in target_path.glob(pattern) if f.is_file()]
            if ext_filter:
                files = [f for f in files if f.suffix.lower() in ext_filter]
        else:
            self.call_from_thread(
                self._add_row, "ERR", str(target), "Path not found", "—", True
            )
            return

        for f in sorted(files):
            try:
                report = scan_file(str(f), password=password)
                self.call_from_thread(self._handle_report, report)
            except Exception as e:
                self.call_from_thread(
                    self._add_row, "ERR", f.name,
                    str(e)[:60], "—", False
                )

        self.call_from_thread(self._scan_complete)

    def _handle_report(self, report: dict) -> None:
        suspicious = report['overall_suspicious']
        self._scan_count += 1
        if suspicious:
            self._suspicious_count += 1

        status   = "[red]SUSPICIOUS[/red]" if suspicious else "[green]CLEAN[/green]"
        filename = Path(report['file']).name
        n        = len(report['findings'])
        methods  = ", ".join(f['method'] for f in report['findings'][:3])
        if n > 3:
            methods += f" +{n - 3} more"
        size_kb  = f"{report['size'] / 1024:.1f} KB"

        finding_text = methods if methods else "—"
        self._add_row(status, filename, finding_text, size_kb, suspicious)
        self._update_stats()

        # Show extraction result if present
        ep = report.get('extracted_payload')
        if ep:
            try:
                text = ep['content'].decode('utf-8')
                preview = text[:60] + ('...' if len(text) > 60 else '')
            except Exception:
                preview = f"(binary {len(ep['content'])} bytes)"
            self._add_row(
                "[cyan]EXTRACTED[/cyan]",
                f"  └─ {ep['method']}",
                preview, "—", False
            )

    def _add_row(self, status, filename, findings, size, suspicious=False):
        table = self.query_one("#scan-table", DataTable)
        table.add_row(status, filename, findings, size)

    def _update_stats(self):
        stats = self.query_one("#scan-stats", Static)
        color = "red" if self._suspicious_count else "green"
        stats.update(
            f"  Scanned: {self._scan_count}  |  "
            f"[{color}]Suspicious: {self._suspicious_count}[/{color}]"
        )

    def _scan_complete(self):
        color = "red" if self._suspicious_count else "green"
        stats = self.query_one("#scan-stats", Static)
        stats.update(
            f"  Scan complete — {self._scan_count} files  |  "
            f"[{color} bold]{self._suspicious_count} suspicious[/{color} bold]"
        )

    @on(Button.Pressed, "#btn-clear")
    def clear_results(self) -> None:
        table = self.query_one("#scan-table", DataTable)
        table.clear()
        self._scan_count       = 0
        self._suspicious_count = 0
        self._update_stats()

    @on(Button.Pressed, "#btn-back")
    def action_back(self): self.app.pop_screen()


# ─────────────────────────────────────────────────────────────────────────────
#  APP
# ─────────────────────────────────────────────────────────────────────────────

class NullTraceApp(App):
    """NullTrace — Multi-carrier steganography toolkit."""

    TITLE   = "NullTrace"
    CSS_PATH = None   # All CSS is inline per-screen

    DEFAULT_CSS = """
    Screen {
        background: #0a0a0a;
    }
    Header {
        background: #0d2a0d;
        color: #00ff41;
    }
    Footer {
        background: #0d1a0d;
        color: #335533;
    }
    """

    def on_mount(self) -> None:
        self.push_screen(SplashScreen())


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app = NullTraceApp()
    app.run()
