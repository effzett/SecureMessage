"""Grafische Oberfläche von SecureMessage (PySide6)."""
import sys

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QFont, QFontDatabase, QGuiApplication
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QTabWidget, QVBoxLayout, QWidget,
)

from securemessage.crypto import decrypt, encrypt, extract_label

APP_NAME = "SecureMessage"
APP_VERSION = "1.1.1"
APP_AUTHOR = "fz@zenmeister.de"
LABELS = [f"{letter}{number:02d}" for letter in "ABCDE" for number in range(1, 21)]


class _Signals(QObject):
    done = Signal(str)
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

        task.signals.done.connect(finish)
        task.signals.failed.connect(finish)
        self._tasks.add(task)
        QThreadPool.globalInstance().start(task)

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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} – {APP_AUTHOR}")
        self.resize(640, 620)

        self.encrypt_page = EncryptPage()
        self.decrypt_page = DecryptPage()
        tabs = QTabWidget()
        tabs.addTab(self.encrypt_page, "Verschlüsseln")
        tabs.addTab(self.decrypt_page, "Entschlüsseln")

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
        super().closeEvent(event)


def run() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    window = MainWindow()
    window.show()
    return app.exec()
