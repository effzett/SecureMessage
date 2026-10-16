"""Grafische Oberfläche von SecureMessage (PySide6)."""
import sys
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

from securemessage.crypto import decrypt, encrypt, extract_label
from securemessage.filecrypto import (
    HEADER_LEN, MAX_TOTAL_BYTES, PlainFile, decrypt_files, encrypt_files,
    extract_file_label, is_smf,
)

APP_NAME = "SecureMessage"
APP_VERSION = "1.2.0"
APP_AUTHOR = "fz@zenmeister.de"
LABELS = [f"{letter}{number:02d}" for letter in "ABCDE" for number in range(1, 21)]


class _Signals(QObject):
    done = Signal(object)
    failed = Signal(str)


class _CryptoTask(QRunnable):
    """Führt die (bewusst langsame) Argon2-Schlüsselableitung im Hintergrund aus."""

    def __init__(self, func, *args):
        super().__init__()
        self.func, self.args = func, args
        self.signals = _Signals()

    def run(self):
        try:
            result = self.func(*self.args)
        except ValueError as exc:
            self.signals.failed.emit(str(exc))
        except OSError as exc:
            self.signals.failed.emit(f"Dateifehler: {exc.strerror or exc}")
        except MemoryError:
            self.signals.failed.emit("Nicht genug Arbeitsspeicher.")
        except Exception:  # keine Interna an die Oberfläche geben
            self.signals.failed.emit("Unerwarteter Fehler bei der Verarbeitung.")
        else:
            self.signals.done.emit(result)


def _password_field() -> tuple[QLineEdit, QCheckBox]:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.Password)
    field.setPlaceholderText("Passwort vom Papier eintippen")
    show = QCheckBox("anzeigen")
    show.toggled.connect(
        lambda on: field.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password))
    return field, show


def _form() -> QFormLayout:
    form = QFormLayout()
    # macOS lässt Felder sonst schmal; Passwortfeld soll die Breite nutzen.
    form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
    return form


def _mono() -> QFont:
    return QFontDatabase.systemFont(QFontDatabase.FixedFont)


class _Page(QWidget):
    """Gemeinsame Teile beider Modi: Status, Hintergrundaufgabe, Kopieren."""

    def __init__(self):
        super().__init__()
        self.status = QLabel()
        self.status.setWordWrap(True)
        self._tasks = set()

    def _set_status(self, text: str, error: bool = False):
        self.status.setStyleSheet("color: #c62828;" if error else "")
        self.status.setText(text)

    def _start(self, task: _CryptoTask, busy_widgets):
        for widget in busy_widgets:
            widget.setEnabled(False)
        QGuiApplication.setOverrideCursor(Qt.WaitCursor)
        self._set_status("Bitte warten …")

        def finish():
            QGuiApplication.restoreOverrideCursor()
            for widget in busy_widgets:
                widget.setEnabled(True)
            self._tasks.discard(task)
            self._after_task()

        task.signals.done.connect(finish)
        task.signals.failed.connect(finish)
        self._tasks.add(task)
        QThreadPool.globalInstance().start(task)

    def _after_task(self):
        """Hook für Seiten, die nach einer Aufgabe ihren Zustand neu setzen."""

    def _copy(self, text: str):
        if text:
            QGuiApplication.clipboard().setText(text)
            self._set_status("In die Zwischenablage kopiert.")


class EncryptPage(_Page):
    def __init__(self):
        super().__init__()
        self.label = QComboBox()
        self.label.addItems(LABELS)
        self.password, show = _password_field()
        self.message = QPlainTextEdit()
        self.message.setPlaceholderText("Nachricht hier eingeben …")
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setFont(_mono())
        self.result.setPlaceholderText("Hier erscheint der verschlüsselte Text (SM1:…)")

        self.run_button = QPushButton("Verschlüsseln")
        self.run_button.setDefault(True)
        self.copy_button = QPushButton("Ergebnis kopieren")
        clear_button = QPushButton("Alles leeren")

        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password, 1)
        pw_row.addWidget(show)
        form = _form()
        form.addRow("Kennung:", self.label)
        form.addRow("Passwort:", pw_row)

        buttons = QHBoxLayout()
        buttons.addWidget(self.run_button)
        buttons.addWidget(self.copy_button)
        buttons.addStretch(1)
        buttons.addWidget(clear_button)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(QLabel("Nachricht:"))
        layout.addWidget(self.message, 2)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Ergebnis (über WhatsApp senden):"))
        layout.addWidget(self.result, 1)
        layout.addWidget(self.status)

        self.run_button.clicked.connect(self._encrypt)
        self.password.returnPressed.connect(self._encrypt)
        self.copy_button.clicked.connect(lambda: self._copy(self.result.toPlainText()))
        clear_button.clicked.connect(self.clear)

    def _encrypt(self):
        if not self.run_button.isEnabled():
            return
        task = _CryptoTask(encrypt, self.label.currentText(), self.password.text(),
                           self.message.toPlainText())
        self.password.clear()
        task.signals.done.connect(self._done)
        task.signals.failed.connect(lambda msg: self._set_status(msg, error=True))
        self._start(task, [self.run_button, self.copy_button])

    def _done(self, text: str):
        self.result.setPlainText(text)
        self._set_status(f"Verschlüsselt mit Kennung {self.label.currentText()}. "
                         "Ergebnis kopieren und versenden.")

    def clear(self):
        for widget in (self.password, self.message, self.result):
            widget.clear()
        self._set_status("")


class DecryptPage(_Page):
    def __init__(self):
        super().__init__()
        self.message = QPlainTextEdit()
        self.message.setFont(_mono())
        self.message.setPlaceholderText("Vollständigen SM1:…-Text hier einfügen")
        self.label = QLabel("–")
        bold = self.label.font()
        bold.setBold(True)
        self.label.setFont(bold)
        self.password, show = _password_field()
        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setPlaceholderText("Hier erscheint die entschlüsselte Nachricht")

        self.run_button = QPushButton("Entschlüsseln")
        self.run_button.setDefault(True)
        paste_button = QPushButton("Einfügen")
        self.copy_button = QPushButton("Nachricht kopieren")
        clear_button = QPushButton("Alles leeren")

        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password, 1)
        pw_row.addWidget(show)
        form = _form()
        form.addRow("Erkannte Kennung:", self.label)
        form.addRow("Passwort:", pw_row)

        top = QHBoxLayout()
        top.addWidget(QLabel("Verschlüsselter Text:"))
        top.addStretch(1)
        top.addWidget(paste_button)

        buttons = QHBoxLayout()
        buttons.addWidget(self.run_button)
        buttons.addWidget(self.copy_button)
        buttons.addStretch(1)
        buttons.addWidget(clear_button)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.message, 1)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(QLabel("Nachricht:"))
        layout.addWidget(self.result, 2)
        layout.addWidget(self.status)

        self.message.textChanged.connect(self._detect_label)
        paste_button.clicked.connect(
            lambda: self.message.setPlainText(QGuiApplication.clipboard().text()))
        self.run_button.clicked.connect(self._decrypt)
        self.password.returnPressed.connect(self._decrypt)
        self.copy_button.clicked.connect(lambda: self._copy(self.result.toPlainText()))
        clear_button.clicked.connect(self.clear)

    def _detect_label(self):
        text = self.message.toPlainText().strip()
        self.result.clear()
        if not text:
            self.label.setText("–")
            self._set_status("")
            return
        try:
            label = extract_label(text)
        except ValueError as exc:
            self.label.setText("–")
            self._set_status(str(exc), error=True)
        else:
            self.label.setText(label)
            self._set_status(f"Passwort für Kennung {label} vom Papier eintippen.")
            self.password.setFocus()

    def _decrypt(self):
        if not self.run_button.isEnabled():
            return
        task = _CryptoTask(decrypt, self.message.toPlainText(), self.password.text())
        self.password.clear()
        task.signals.done.connect(self._done)
        task.signals.failed.connect(lambda msg: self._set_status(msg, error=True))
        self._start(task, [self.run_button, self.copy_button])

    def _done(self, text: str):
        self.result.setPlainText(text)
        self._set_status("Nachricht erfolgreich entschlüsselt und geprüft.")

    def clear(self):
        for widget in (self.message, self.password, self.result):
            widget.clear()
        self._set_status("")


def _format_size(size: int) -> str:
    for unit in ("Byte", "KB", "MB"):
        if size < 1024 or unit == "MB":
            return f"{size:.0f} {unit}" if unit == "Byte" else f"{size:.1f} {unit}"
        size /= 1024


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _unique_path(folder: Path, name: str) -> Path:
    """Vorhandene Dateien nie überschreiben: "a.txt" -> "a (1).txt" usw."""
    candidate = folder / name
    stem, suffix = Path(name).stem, Path(name).suffix
    number = 1
    while candidate.exists():
        candidate = folder / f"{stem} ({number}){suffix}"
        number += 1
    return candidate


def _encrypt_to_file(label: str, password: str, paths: list[Path], target: Path) -> str:
    files = [PlainFile(path.name, path.read_bytes()) for path in paths]
    target.write_bytes(encrypt_files(label, password, files))
    return str(target)


class _DropList(QListWidget):
    """Liste, auf die man Dateien aus Finder/Explorer ziehen kann."""

    files_dropped = Signal(list)

    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DropOnly)
        self.setSelectionMode(QAbstractItemView.NoSelection)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        self.dragEnterEvent(event)

    def dropEvent(self, event):
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self.files_dropped.emit(paths)


class FilesPage(_Page):
    """Dateien zu einer .smf-Datei verschlüsseln oder eine .smf-Datei entschlüsseln."""

    def __init__(self):
        super().__init__()
        self._paths: list[Path] = []          # Verschlüsseln: ausgewählte Dateien
        self._smf: bytes | None = None        # Entschlüsseln: Inhalt der .smf-Datei
        self._smf_name = ""
        self._plain: list[PlainFile] = []     # Entschlüsselte Dateien (nur im Speicher)

        hint = QLabel("Dateien zum Verschlüsseln oder eine .smf-Datei zum Entschlüsseln "
                      "hier hineinziehen:")
        hint.setWordWrap(True)
        self.list = _DropList()
        self.mode = QLabel()
        bold = self.mode.font()
        bold.setBold(True)
        self.mode.setFont(bold)
        self.mode.setWordWrap(True)
        self.label = QComboBox()
        self.label.addItems(LABELS)
        self.password, show = _password_field()

        pick_button = QPushButton("Dateien auswählen …")
        clear_button = QPushButton("Alles leeren")
        self.run_button = QPushButton()
        self.run_button.setDefault(True)
        self.save_button = QPushButton("Speichern unter …")

        top = QHBoxLayout()
        top.addWidget(pick_button)
        top.addStretch(1)
        top.addWidget(clear_button)
        pw_row = QHBoxLayout()
        pw_row.addWidget(self.password, 1)
        pw_row.addWidget(show)
        form = _form()
        form.addRow("Kennung:", self.label)
        form.addRow("Passwort:", pw_row)
        buttons = QHBoxLayout()
        buttons.addWidget(self.run_button)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)

        layout = QVBoxLayout(self)
        layout.addWidget(hint)
        layout.addWidget(self.list, 1)
        layout.addLayout(top)
        layout.addWidget(self.mode)
        layout.addLayout(form)
        layout.addLayout(buttons)
        layout.addWidget(self.status)

        self.list.files_dropped.connect(self.add_paths)
        pick_button.clicked.connect(self._pick)
        clear_button.clicked.connect(self.clear)
        self.run_button.clicked.connect(self._run)
        self.password.returnPressed.connect(self._run)
        self.save_button.clicked.connect(self._save_dialog)
        self._refresh()

    # ----- Zustand -------------------------------------------------------
    def _refresh(self):
        self.list.clear()
        if self._plain:
            for item in self._plain:
                self.list.addItem(f"{item.name}  ({_format_size(len(item.data))})")
            total = sum(len(item.data) for item in self._plain)
            self.mode.setText(f"Entschlüsselt: {len(self._plain)} Datei(en), "
                              f"{_format_size(total)}. Mit „Speichern unter …“ ablegen.")
        elif self._smf is not None:
            self.list.addItem(f"{self._smf_name}  ({_format_size(len(self._smf))})")
            self.mode.setText("Entschlüsseln: Passwort für die erkannte Kennung eingeben.")
        elif self._paths:
            for path in self._paths:
                self.list.addItem(f"{path.name}  ({_format_size(_size(path))})")
            total = sum(_size(path) for path in self._paths)
            self.mode.setText(f"Verschlüsseln: {len(self._paths)} Datei(en), "
                              f"{_format_size(total)} von höchstens 200 MB.")
        else:
            self.mode.setText("")
        decrypt_mode = self._smf is not None
        self.label.setEnabled(not decrypt_mode)
        self.run_button.setText("Entschlüsseln" if decrypt_mode else "Verschlüsseln und speichern …")
        self.run_button.setEnabled(bool(self._paths or self._smf) and not self._plain)
        self.save_button.setEnabled(bool(self._plain))

    def _after_task(self):
        self._refresh()

    def add_paths(self, raw_paths: list[str]):
        paths = [Path(p) for p in raw_paths]
        if any(not p.is_file() for p in paths):
            self._set_status("Ordner werden nicht unterstützt, bitte einzelne Dateien wählen.",
                             error=True)
            return
        if self._smf is not None or self._plain:
            self.clear()
        if not self._paths and len(paths) == 1 and self._looks_like_smf(paths[0]):
            self._load_smf(paths[0])
            return
        known = {p.resolve() for p in self._paths}
        self._paths += [p for p in paths if p.resolve() not in known]
        self._set_status("")
        self._refresh()

    @staticmethod
    def _looks_like_smf(path: Path) -> bool:
        with path.open("rb") as handle:
            return is_smf(handle.read(HEADER_LEN))

    def _load_smf(self, path: Path):
        if path.stat().st_size > MAX_TOTAL_BYTES + 16 * 1024 * 1024:
            self._set_status("Die .smf-Datei ist zu groß.", error=True)
            return
        data = path.read_bytes()
        try:
            label = extract_file_label(data)
        except ValueError as exc:
            self._set_status(str(exc), error=True)
            return
        self._smf, self._smf_name = data, path.name
        self.label.setCurrentText(label)
        self._set_status(f"Erkannte Kennung: {label}. Passwort vom Papier eintippen.")
        self._refresh()
        self.password.setFocus()

    def clear(self):
        self._paths, self._smf, self._smf_name, self._plain = [], None, "", []
        self.password.clear()
        self._set_status("")
        self._refresh()

    # ----- Aktionen ------------------------------------------------------
    def _pick(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Dateien auswählen")
        if paths:
            self.add_paths(paths)

    def _run(self):
        if not self.run_button.isEnabled():
            return
        if self._smf is not None:
            self.decrypt_now()
            return
        target, _ = QFileDialog.getSaveFileName(
            self, "Verschlüsselte Datei speichern",
            f"SecureMessage-{self.label.currentText()}.smf", "SecureMessage (*.smf)")
        if target:
            if not target.lower().endswith(".smf"):
                target += ".smf"
            self.encrypt_to(Path(target))

    def encrypt_to(self, target: Path):
        if sum(_size(path) for path in self._paths) > MAX_TOTAL_BYTES:
            self._set_status("Dateien sind zusammen größer als 200 MB.", error=True)
            return
        task = _CryptoTask(_encrypt_to_file, self.label.currentText(), self.password.text(),
                           list(self._paths), target)
        self.password.clear()
        task.signals.done.connect(lambda path: self._set_status(
            f"Gespeichert: {path}\nDiese Datei als Dokument über WhatsApp senden."))
        task.signals.failed.connect(lambda msg: self._set_status(msg, error=True))
        self._start(task, [self.run_button, self.save_button])

    def decrypt_now(self):
        task = _CryptoTask(decrypt_files, self._smf, self.password.text())
        self.password.clear()
        task.signals.done.connect(self._decrypted)
        task.signals.failed.connect(lambda msg: self._set_status(msg, error=True))
        self._start(task, [self.run_button, self.save_button])

    def _decrypted(self, files: list):
        self._plain = files
        self._set_status("Datei erfolgreich entschlüsselt und geprüft.")

    def _save_dialog(self):
        if len(self._plain) == 1:
            target, _ = QFileDialog.getSaveFileName(self, "Datei speichern", self._plain[0].name)
            if target:
                self.save_to(Path(target))
        elif self._plain:
            folder = QFileDialog.getExistingDirectory(self, "Ordner zum Speichern wählen")
            if folder:
                self.save_to(Path(folder))

    def save_to(self, target: Path):
        """Einzeldatei: target ist der Dateipfad. Mehrere: target ist ein Ordner."""
        try:
            if len(self._plain) == 1 and not target.is_dir():
                target.write_bytes(self._plain[0].data)
                written = [target]
            else:
                written = []
                for item in self._plain:
                    path = _unique_path(target, item.name)
                    path.write_bytes(item.data)
                    written.append(path)
        except OSError as exc:
            self._set_status(f"Dateifehler: {exc.strerror or exc}", error=True)
            return
        where = written[0] if len(written) == 1 else target
        self._set_status(f"{len(written)} Datei(en) gespeichert in: {where}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} – {APP_AUTHOR}")
        self.resize(660, 640)

        self.encrypt_page = EncryptPage()
        self.decrypt_page = DecryptPage()
        self.files_page = FilesPage()
        tabs = QTabWidget()
        tabs.addTab(self.encrypt_page, "Verschlüsseln")
        tabs.addTab(self.decrypt_page, "Entschlüsseln")
        tabs.addTab(self.files_page, "Dateien")

        clipboard_button = QPushButton("Zwischenablage leeren")
        clipboard_button.clicked.connect(self._clear_clipboard)
        hint = QLabel("Offline · speichert keine Passwörter oder Nachrichten")
        hint.setStyleSheet("color: gray;")
        bottom = QHBoxLayout()
        bottom.addWidget(hint, 1)
        bottom.addWidget(clipboard_button)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.addWidget(tabs)
        layout.addLayout(bottom)
        self.setCentralWidget(central)

    def _clear_clipboard(self):
        QGuiApplication.clipboard().clear()
        QMessageBox.information(
            self, APP_NAME,
            "Die Zwischenablage wurde geleert.\n\n"
            "Hinweis: Clipboard-Manager oder Cloud-Synchronisierung können "
            "Inhalte trotzdem behalten haben.")

    def closeEvent(self, event):
        QThreadPool.globalInstance().waitForDone()
        self.encrypt_page.clear()
        self.decrypt_page.clear()
        self.files_page.clear()
        super().closeEvent(event)


def run() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    window = MainWindow()
    window.show()
    return app.exec()
