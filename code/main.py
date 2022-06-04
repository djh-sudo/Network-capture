# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'connect_me.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

import sys

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5 import QtWidgets
from mainwindow import Ui_MainWindow
import rosource_rc


class MyMainForm(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MyMainForm, self).__init__(parent)
        self.setupUi(self)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    form = QtWidgets.QMainWindow()
    w = MyMainForm()
    form.setWindowIcon(QIcon(':/img/analysis.png'))
    w.setupUi(form)
    form.show()
    sys.exit(app.exec_())

