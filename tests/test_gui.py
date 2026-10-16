import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication

from securemessage.gui import APP_AUTHOR, APP_VERSION, MainWindow


class GuiRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = MainWindow()

    def tearDown(self):
        self.window.close()

    def _wait(self):
        QThreadPool.globalInstance().waitForDone()
        self.app.processEvents()

    def test_encrypt_then_decrypt(self):
        enc, dec = self.window.encrypt_page, self.window.decrypt_page
        enc.label.setCurrentText("C07")
        enc.password.setText("Papier-Passwort 1")
        enc.message.setPlainText("Hallo Welt – äöü ß")
        enc.run_button.click()
        self._wait()
        ciphertext = enc.result.toPlainText()
        self.assertTrue(ciphertext.startswith("SM1:C07:"))
        self.assertEqual(enc.password.text(), "", "Passwortfeld muss geleert sein")

        dec.message.setPlainText(ciphertext)
        self.assertEqual(dec.label.text(), "C07")
        dec.password.setText("Papier-Passwort 1")
        dec.run_button.click()
        self._wait()
        self.assertEqual(dec.result.toPlainText(), "Hallo Welt – äöü ß")
        self.assertEqual(dec.password.text(), "")

    def test_wrong_password_rejected(self):
        enc, dec = self.window.encrypt_page, self.window.decrypt_page
        enc.password.setText("richtig")
        enc.message.setPlainText("geheim")
        enc.run_button.click()
        self._wait()
        dec.message.setPlainText(enc.result.toPlainText())
        dec.password.setText("falsch")
        dec.run_button.click()
        self._wait()
        self.assertEqual(dec.result.toPlainText(), "")
        self.assertIn("fehlgeschlagen", dec.status.text())

    def test_title_shows_version_and_author(self):
        title = self.window.windowTitle()
        self.assertIn(APP_VERSION, title)
        self.assertIn(APP_AUTHOR, title)

    def test_invalid_format_shows_error(self):
        dec = self.window.decrypt_page
        dec.message.setPlainText("Hallo, das ist keine SM1-Nachricht")
        self.assertEqual(dec.label.text(), "–")
        self.assertIn("SM1", dec.status.text())


if __name__ == "__main__":
    unittest.main()
