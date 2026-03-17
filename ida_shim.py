try:
    from PyQt5.QtGui import QClipboard
    from PyQt5.QtWidgets import QApplication
except ImportError:
    from PySide6.QtGui import QClipboard
    from PySide6.QtWidgets import QApplication
