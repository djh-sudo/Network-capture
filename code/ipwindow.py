# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'ipwindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

import os
import re
import shutil
import threading
import time

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QTableWidget, QAbstractItemView, QTableWidgetItem
from analysis_data import analysis_ip, plot_src, plot_des, lookup
import rosource_rc


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1236, 739)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.widget = QtWidgets.QWidget(self.centralwidget)
        self.widget.setObjectName("widget")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout.setContentsMargins(1, 1, 1, 1)
        self.horizontalLayout.setSpacing(1)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_3 = QtWidgets.QLabel(self.widget)
        self.label_3.setMinimumSize(QtCore.QSize(150, 16))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout.addWidget(self.label_3)
        self.lineEdit = QtWidgets.QLineEdit(self.widget)
        self.lineEdit.setMinimumSize(QtCore.QSize(50, 25))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lineEdit.setFont(font)
        self.lineEdit.setObjectName("lineEdit")
        self.horizontalLayout.addWidget(self.lineEdit)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.pushButton_2 = QtWidgets.QPushButton(self.widget)
        self.pushButton_2.setMinimumSize(QtCore.QSize(95, 0))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout.addWidget(self.pushButton_2)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.pushButton_3 = QtWidgets.QPushButton(self.widget)
        self.pushButton_3.setMinimumSize(QtCore.QSize(95, 0))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout.addWidget(self.pushButton_3)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem2)
        self.label_4 = QtWidgets.QLabel(self.widget)
        self.label_4.setMinimumSize(QtCore.QSize(50, 16))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout.addWidget(self.label_4)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem3)
        self.lineEdit_2 = QtWidgets.QLineEdit(self.widget)
        self.lineEdit_2.setMinimumSize(QtCore.QSize(400, 25))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.lineEdit_2.setFont(font)
        self.lineEdit_2.setText("")
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.horizontalLayout.addWidget(self.lineEdit_2)
        self.pushButton = QtWidgets.QPushButton(self.widget)
        self.pushButton.setMinimumSize(QtCore.QSize(95, 0))
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout.addWidget(self.pushButton)
        self.verticalLayout.addWidget(self.widget)
        self.splitter = QtWidgets.QSplitter(self.centralwidget)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName("splitter")
        self.label = QtWidgets.QLabel(self.splitter)
        self.label.setMinimumSize(QtCore.QSize(0, 200))
        self.label.setText("")
        self.label.setObjectName("label")
        self.tableWidget = QtWidgets.QTableWidget(self.splitter)
        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setPointSize(10)
        font.setBold(True)
        font.setWeight(75)
        self.tableWidget.setFont(font)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(0)
        self.tableWidget.setRowCount(0)
        self.verticalLayout.addWidget(self.splitter)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1236, 26))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.init_GUI()
        self.init_signal_slot()

        # init

    def init_GUI(self):
        self.tableWidget.setColumnCount(7)
        self.tableWidget.setRowCount(0)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.verticalHeader().setDefaultSectionSize(30)
        self.lineEdit.setText('10')
        self.tableWidget.setHorizontalHeaderLabels(
            ['NO.', 'IP addr', 'Location', 'Send Count', 'Send Size', 'Recv Count', 'Recv Size'])
        self.tableWidget.setColumnWidth(0, 50)
        self.tableWidget.setColumnWidth(1, 250)
        self.tableWidget.setColumnWidth(2, 250)
        self.tableWidget.setColumnWidth(3, 250)
        self.tableWidget.setColumnWidth(4, 250)
        self.tableWidget.setColumnWidth(5, 250)
        self.tableWidget.setColumnWidth(6, 250)

        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget.setSelectionMode(QAbstractItemView.SingleSelection)

        if os.path.exists('./Cache'):
            shutil.rmtree('./Cache')
            os.mkdir('./Cache')
        self.pro = []
        self.flag = True
        self.statusbar.showMessage('分析中 ...')

    def init_signal_slot(self):
        self.lineEdit_2.returnPressed.connect(self.drop_data)
        self.pushButton.clicked.connect(self.drop_data)
        self.pushButton_3.clicked.connect(self.plot_raw_data)
        self.pushButton_2.clicked.connect(self.change_status)

    def init_show(self):
        if not self.pro:
            return
        self.res, self.src_len, self.des_len = analysis_ip(self.pro)
        plot_src(self.src_len)
        plot_des(self.des_len)
        self.tableWidget.setSortingEnabled(False)
        for it in range(len(self.res)):
            item = self.res[it]
            cur_row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(cur_row)
            indx = QTableWidgetItem()
            indx.setData(QtCore.Qt.DisplayRole, it)
            self.tableWidget.setItem(cur_row, 0, indx)
            self.tableWidget.setItem(cur_row, 1, QTableWidgetItem(item.ip_addr))
            if item.location:
                self.tableWidget.setItem(cur_row, 2, QTableWidgetItem(item.location))
            else:
                t = threading.Thread(target=self.fill_location, args=(item.ip_addr, it,))
                t.setDaemon(True)
                t.start()
            indx_src_count = QTableWidgetItem()
            indx_src_count.setData(QtCore.Qt.DisplayRole, item.send_count)
            self.tableWidget.setItem(cur_row, 3, indx_src_count)
            indx_src_size = QTableWidgetItem()
            indx_src_size.setData(QtCore.Qt.DisplayRole, item.send_size)
            self.tableWidget.setItem(cur_row, 4, indx_src_size)

            indx_des_count = QTableWidgetItem()
            indx_des_count.setData(QtCore.Qt.DisplayRole, item.recv_count)
            self.tableWidget.setItem(cur_row, 5, indx_des_count)
            indx_des_size = QTableWidgetItem()
            indx_des_size.setData(QtCore.Qt.DisplayRole, item.recv_size)
            self.tableWidget.setItem(cur_row, 6, indx_des_size)

        self.tableWidget.setSortingEnabled(True)
        self.draw_src_ip()
        self.statusbar.showMessage('分析完成')

    def fill_location(self, ip_addr, i):
        time.sleep(0.5)
        request = lookup(ip_addr)
        self.tableWidget.setItem(i, 2, QTableWidgetItem(request))
        return

    def draw_src_ip(self):
        cache = './Cache/'
        if os.path.exists(cache + 'ip_src.png'):
            pixmap = QPixmap(cache + 'ip_src.png')
            self.label.setPixmap(pixmap)
            self.label.setAlignment(Qt.AlignCenter)
            self.label.setScaledContents(True)
        else:
            return

    def drop_data(self):
        conditon = self.lineEdit_2.text().replace(' ', '')
        if conditon == '':
            self.lineEdit_2.setStyleSheet("""QLineEdit { background-color: green; color: white }""")
            self.conditon_show()
            self.statusbar.showMessage('隐藏数据包:0条,总数:' + str(self.tableWidget.rowCount()))
            return
        regProtocol = r"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])[\\.]){3}(25[0-5]|2[0-4][0-9]|1[" \
                      "0-9][0-9]|[1-9][" \
                      "0-9]|[0-9])|"
        pattern = re.compile(regProtocol)
        res = re.fullmatch(pattern, conditon)
        if res:
            self.lineEdit_2.setStyleSheet("""QLineEdit { background-color: green; color: white }""")
            ex = self.check_condition(res.group())
            self.conditon_show(ex)
            self.statusbar.showMessage('隐藏数据包: ' + str(len(ex)) + '条, 总数:' + str(self.tableWidget.rowCount()))
        else:
            self.lineEdit_2.setStyleSheet("""QLineEdit { background-color: red; color: white }""")

    def check_condition(self, ip_addr):
        exclude = set()
        row_number = self.tableWidget.rowCount()
        for i in range(row_number):
            if self.tableWidget.item(i, 1).text() == ip_addr:
                continue
            else:
                exclude.add(i)
        return exclude

    def conditon_show(self, exclude=set()):
        row_number = self.tableWidget.rowCount()
        for it in range(row_number):
            if it in exclude:
                self.tableWidget.setRowHidden(it, True)
            else:
                self.tableWidget.setRowHidden(it, False)

    def plot_raw_data(self):
        number = int(self.lineEdit.text())
        if not number:
            return
        if self.flag:
            plot_src(self.src_len, number, True)
        else:
            plot_des(self.des_len, number, True)

    def change_status(self):
        cache = './Cache/'
        self.flag = not self.flag
        if self.flag and os.path.exists(cache + 'ip_src.png'):
            pixmap = QPixmap(cache + 'ip_src.png')
            self.label.setPixmap(pixmap)
            self.label.setAlignment(Qt.AlignCenter)
            self.label.setScaledContents(True)
        elif not self.flag and os.path.exists(cache + 'ip_des.png'):
            pixmap = QPixmap(cache + 'ip_des.png')
            self.label.setPixmap(pixmap)
            self.label.setAlignment(Qt.AlignCenter)
            self.label.setScaledContents(True)
        else:
            return

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "ip地址分析"))
        self.label_3.setText(_translate("MainWindow", "绘制数据包数量"))
        self.pushButton_2.setText(_translate("MainWindow", "切换"))
        self.pushButton_3.setText(_translate("MainWindow", "显示原图"))
        self.label_4.setText(_translate("MainWindow", "筛选"))
        self.pushButton.setText(_translate("MainWindow", "确认"))