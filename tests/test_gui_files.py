import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication

from securemessage.gui import MainWindow

PW = "Papier-Passwort 1"


class FilesTabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.window = MainWindow()
        self.page = self.window.files_page

    def tearDown(self):
        self.window.close()
        self.tmp.cleanup()

    def _wait(self):
        QThreadPool.globalInstance().waitForDone()
        self.app.processEvents()

    def _make(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return str(path)

    def _encrypt(self, files, label="B12"):
        self.page.add_paths([self._make(n, d) for n, d in files])
        self.page.label.setCurrentText(label)
        self.page.password.setText(PW)
        target = self.dir / "paket.smf"
        self.page.encrypt_to(target)
        self._wait()
        self.assertTrue(target.exists(), self.page.status.text())
        self.assertEqual(self.page.password.text(), "")
        return target

    def test_single_file_roundtrip(self):
        data = os.urandom(20000)
        smf = self._encrypt([("Foto.jpg", data)])
        self.page.clear()

        self.page.add_paths([str(smf)])
        self.assertEqual(self.page.label.currentText(), "B12")
        self.assertFalse(self.page.label.isEnabled())
        self.page.password.setText(PW)
        self.page.decrypt_now()
        self._wait()
        self.assertTrue(self.page.save_button.isEnabled())

        out = self.dir / "ausgabe"
        out.mkdir()
        self.page.save_to(out / "Foto.jpg")
        self.assertEqual((out / "Foto.jpg").read_bytes(), data)

    def test_multiple_files_never_overwrite(self):
        smf = self._encrypt([("a.txt", b"eins"), ("b.txt", b"zwei")])
        self.page.clear()
        self.page.add_paths([str(smf)])
        self.page.password.setText(PW)
        self.page.decrypt_now()
        self._wait()

        out = self.dir / "ziel"
        out.mkdir()
        (out / "a.txt").write_bytes(b"vorhanden")
        self.page.save_to(out)
        self.assertEqual((out / "a.txt").read_bytes(), b"vorhanden")
        self.assertEqual((out / "a (1).txt").read_bytes(), b"eins")
        self.assertEqual((out / "b.txt").read_bytes(), b"zwei")

    def test_wrong_password(self):
        smf = self._encrypt([("a.txt", b"geheim")])
        self.page.clear()
        self.page.add_paths([str(smf)])
        self.page.password.setText("falsch")
        self.page.decrypt_now()
        self._wait()
        self.assertFalse(self.page.save_button.isEnabled())
        self.assertIn("fehlgeschlagen", self.page.status.text())

    def test_folders_rejected(self):
        self.page.add_paths([str(self.dir)])
        self.assertIn("Ordner", self.page.status.text())
        self.assertFalse(self.page.run_button.isEnabled())


if __name__ == "__main__":
    unittest.main()
