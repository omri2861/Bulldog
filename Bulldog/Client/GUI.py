# ------------------------------------------------------------------------------------------
# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'F:\Cyber\Bulldog\gui\expiremental.ui'
#
# Created by: PyQt4 UI code generator 4.11.4
#
# WARNING! All changes made in this file will be lost!

import sys
from PyQt4 import QtCore, QtGui

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:

    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8

    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

# ------------------------------------------------------------------------------------------

"""
This file contains all the GUI elements for Bulldog.
It was mostly generated by Qt Designer and code generator.
"""

TRANSPARENT_BG_IMAGE = "image: rgba(255, 255, 255, 0);"
ENCRYPTION_TAB_TEXT = "Select the encryption type for the chosen files:"
AES_EXPLANATION = "AES- Advanced Encryption Standard.\nStrong, reliable encryption, considered the " \
                  "standard by the U.S. government.\nConsidered slow.Recommended for small or medium sized files."
BLOWFISH_EXPLANATION = "Blowfish- Not as reliable as the AES, but still one of the best\n" \
                       "encryption methods.\nIt is very fast and effective.\nHighly recommended for large" \
                       " files with lots of data."
TDES_EXPLANATION = "Triple DES- Considered slow, but provides extra security,\n" \
                   "as it uses three keys, Recommended for small, important files"
AUTHENTICATION_TEXT = "Please log in to the system, so the encryption could be completed:"
FILE_CHOOSING_TAB_TEXT = "Select the files which should be encrypted:"
BULLDOG_BG_IMAGE = "image: url(:/images/bulldog_transperant.png);"
GREY_BACKGROUND = "background-color: rgb(240, 240, 240, 180);"
WHITE_BACKGROUND = "background-color: rgba(255, 255, 255, 255);"
MODE_TDES = 1
MODE_AES = 2
MODE_BLOWFISH = 3


class Task(object):
    """
    This class wil describe which files should be encrypted and how.
    """
    def __init__(self, method, username, password, path):
        """
        :param method: The selected encryption method.
        :param username: The selected username.
        :param password: The selected password.
        :param path: The selected path.
        """
        self.method = method
        self.username = username
        self.password = password
        self.path = path

    def __str__(self):
        return "method: %s\npath: %s\nusername: %s\npassword: %s" % (self.method, self.path, self.username,
                                                                     self.password)


class EncryptionWindow(QtGui.QMainWindow):
    def __init__(self, path):
        super(EncryptionWindow, self).__init__()

        self.selected_path = path
        self.task = None
        self.setup_ui()

    def setup_ui(self):

        self.setObjectName(_fromUtf8("Bulldog- Encrypt"))
        self.resize(550, 360)
        size_policy = QtGui.QSizePolicy(QtGui.QSizePolicy.Preferred, QtGui.QSizePolicy.Preferred)
        size_policy.setHorizontalStretch(0)
        size_policy.setVerticalStretch(0)
        size_policy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(size_policy)
        self.setMinimumSize(QtCore.QSize(550, 360))
        self.setStyleSheet(_fromUtf8(""))
        self.setDocumentMode(False)
        self.setTabShape(QtGui.QTabWidget.Rounded)
        self.centralwidget = QtGui.QWidget(self)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))
        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.centralwidget)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))

        # Setting the tab widget:
        self.tab_widget = QtGui.QTabWidget(self.centralwidget)
        self.tab_widget.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.tab_widget.setTabPosition(QtGui.QTabWidget.North)
        self.tab_widget.setTabShape(QtGui.QTabWidget.Rounded)
        self.tab_widget.setElideMode(QtCore.Qt.ElideLeft)
        self.tab_widget.setUsesScrollButtons(False)
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setObjectName(_fromUtf8("tab_widget"))

        # Setting the first tab- file selection tab:
        self.file_selection = QtGui.QWidget()
        self.file_selection.setObjectName(_fromUtf8("file_selection"))
        self.verticalLayout = QtGui.QVBoxLayout(self.file_selection)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        spacerItem = QtGui.QSpacerItem(20, 13, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem)
        self.file_selection_label = QtGui.QLabel(self.file_selection)
        self.file_selection_label.setObjectName(_fromUtf8("file_selection_label"))
        self.verticalLayout.addWidget(self.file_selection_label)
        spacerItem1 = QtGui.QSpacerItem(20, 20, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem1)

        # Set up the file- selecting tree widget:
        self.model = QtGui.QFileSystemModel(self.file_selection)
        self.model.setRootPath(_fromUtf8(self.selected_path))
        self.file_selector = QtGui.QTreeView(self.file_selection)
        self.file_selector.setModel(self.model)
        self.file_selector.setRootIndex(self.model.index(self.model.rootPath()))
        self.file_selector.setObjectName(_fromUtf8("file_selector"))
        self.verticalLayout.addWidget(self.file_selector)

        spacerItem2 = QtGui.QSpacerItem(20, 13, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout.addItem(spacerItem2)
        self.button_box_1 = QtGui.QHBoxLayout()
        self.button_box_1.setObjectName(_fromUtf8("button_box_1"))
        spacerItem3 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.button_box_1.addItem(spacerItem3)
        self.cancel_button_1 = QtGui.QPushButton(self.file_selection)
        self.cancel_button_1.setObjectName(_fromUtf8("cancel_button_1"))
        self.button_box_1.addWidget(self.cancel_button_1)
        self.next_button_1 = QtGui.QPushButton(self.file_selection)
        self.next_button_1.setObjectName(_fromUtf8("next_button_1"))
        self.button_box_1.addWidget(self.next_button_1)
        self.verticalLayout.addLayout(self.button_box_1)
        self.tab_widget.addTab(self.file_selection, _fromUtf8(""))

        # Setting up the second tab- the encryption method tab:
        self.encryption_selection = QtGui.QWidget()
        self.encryption_selection.setObjectName(_fromUtf8("encryption_selection"))
        self.verticalLayout_2 = QtGui.QVBoxLayout(self.encryption_selection)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        spacerItem4 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem4)
        self.encryption_label = QtGui.QLabel(self.encryption_selection)
        self.encryption_label.setObjectName(_fromUtf8("encryption_label"))
        self.verticalLayout_2.addWidget(self.encryption_label)
        spacerItem5 = QtGui.QSpacerItem(20, 20, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_2.addItem(spacerItem5)
        self.AES_layout = QtGui.QHBoxLayout()
        self.AES_layout.setObjectName(_fromUtf8("AES_layout"))
        spacerItem6 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.AES_layout.addItem(spacerItem6)
        self.AES_button = QtGui.QRadioButton(self.encryption_selection)
        self.AES_button.setObjectName(_fromUtf8("AES_button"))
        self.AES_layout.addWidget(self.AES_button)
        self.verticalLayout_2.addLayout(self.AES_layout)
        self.blowfish_layout = QtGui.QHBoxLayout()
        self.blowfish_layout.setObjectName(_fromUtf8("blowfish_layout"))
        spacerItem7 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.blowfish_layout.addItem(spacerItem7)
        self.blowfish_button = QtGui.QRadioButton(self.encryption_selection)
        self.blowfish_button.setObjectName(_fromUtf8("blowfish_button"))
        self.blowfish_layout.addWidget(self.blowfish_button)
        self.verticalLayout_2.addLayout(self.blowfish_layout)
        self.TDES_layout = QtGui.QHBoxLayout()
        self.TDES_layout.setObjectName(_fromUtf8("TDES_layout"))
        spacerItem8 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.TDES_layout.addItem(spacerItem8)
        self.TDES_button = QtGui.QRadioButton(self.encryption_selection)
        self.TDES_button.setObjectName(_fromUtf8("TDES_button"))
        self.TDES_layout.addWidget(self.TDES_button)
        self.verticalLayout_2.addLayout(self.TDES_layout)
        spacerItem9 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_2.addItem(spacerItem9)
        self.button_box_2 = QtGui.QHBoxLayout()
        self.button_box_2.setObjectName(_fromUtf8("button_box_2"))
        spacerItem10 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.button_box_2.addItem(spacerItem10)
        self.back_button_1 = QtGui.QPushButton(self.file_selection)
        self.back_button_1.setObjectName(_fromUtf8("back_button_1"))
        self.button_box_2.addWidget(self.back_button_1)
        self.cancel_button_2 = QtGui.QPushButton(self.encryption_selection)
        self.cancel_button_2.setObjectName(_fromUtf8("cancel_button_2"))
        self.button_box_2.addWidget(self.cancel_button_2)
        self.next_button_2 = QtGui.QPushButton(self.encryption_selection)
        self.next_button_2.setObjectName(_fromUtf8("next_button_2"))
        self.button_box_2.addWidget(self.next_button_2)
        self.verticalLayout_2.addLayout(self.button_box_2)
        self.tab_widget.addTab(self.encryption_selection, _fromUtf8(""))

        # Setting up the third tab- authentication tab:
        self.authentication = QtGui.QWidget()
        self.authentication.setObjectName(_fromUtf8("authentication"))
        self.verticalLayout_3 = QtGui.QVBoxLayout(self.authentication)
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        spacerItem11 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_3.addItem(spacerItem11)
        self.auth_label = QtGui.QLabel(self.authentication)
        self.auth_label.setObjectName(_fromUtf8("auth_label"))
        self.verticalLayout_3.addWidget(self.auth_label)
        spacerItem12 = QtGui.QSpacerItem(20, 20, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_3.addItem(spacerItem12)
        self.username_layout = QtGui.QHBoxLayout()
        self.username_layout.setObjectName(_fromUtf8("username_layout"))
        spacerItem13 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.username_layout.addItem(spacerItem13)
        self.username_label = QtGui.QLabel(self.authentication)
        self.username_label.setObjectName(_fromUtf8("username_label"))
        self.username_layout.addWidget(self.username_label)
        spacerItem14 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.username_layout.addItem(spacerItem14)
        self.username_edit = QtGui.QLineEdit(self.authentication)
        self.username_edit.setObjectName(_fromUtf8("username_edit"))
        self.username_layout.addWidget(self.username_edit)
        spacerItem15 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.username_layout.addItem(spacerItem15)
        self.verticalLayout_3.addLayout(self.username_layout)
        spacerItem16 = QtGui.QSpacerItem(20, 10, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Fixed)
        self.verticalLayout_3.addItem(spacerItem16)
        self.password_layout = QtGui.QHBoxLayout()
        self.password_layout.setObjectName(_fromUtf8("password_layout"))
        spacerItem17 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.password_layout.addItem(spacerItem17)
        self.password_label = QtGui.QLabel(self.authentication)
        self.password_label.setObjectName(_fromUtf8("password_label"))
        self.password_layout.addWidget(self.password_label)
        spacerItem18 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Minimum)
        self.password_layout.addItem(spacerItem18)
        self.password_input = QtGui.QLineEdit(self.authentication)
        self.password_input.setFrame(True)
        self.password_input.setEchoMode(QtGui.QLineEdit.Password)
        self.password_input.setObjectName(_fromUtf8("password_input"))
        self.password_layout.addWidget(self.password_input)
        spacerItem19 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.password_layout.addItem(spacerItem19)
        self.verticalLayout_3.addLayout(self.password_layout)
        spacerItem20 = QtGui.QSpacerItem(20, 40, QtGui.QSizePolicy.Minimum, QtGui.QSizePolicy.Expanding)
        self.verticalLayout_3.addItem(spacerItem20)
        self.button_box_3 = QtGui.QHBoxLayout()
        self.button_box_3.setObjectName(_fromUtf8("button_box_3"))
        spacerItem21 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.button_box_3.addItem(spacerItem21)
        self.back_button_2 = QtGui.QPushButton(self.file_selection)
        self.back_button_2.setObjectName(_fromUtf8("back_button_1"))
        self.button_box_3.addWidget(self.back_button_2)

        self.cancel_button_3 = QtGui.QPushButton(self.authentication)
        self.cancel_button_3.setObjectName(_fromUtf8("cancel_button_3"))
        self.button_box_3.addWidget(self.cancel_button_3)
        self.finish_button = QtGui.QPushButton(self.authentication)
        self.finish_button.setObjectName(_fromUtf8("finish_button"))
        self.button_box_3.addWidget(self.finish_button)
        self.verticalLayout_3.addLayout(self.button_box_3)
        self.tab_widget.addTab(self.authentication, _fromUtf8(""))
        self.horizontalLayout_2.addWidget(self.tab_widget)
        self.setCentralWidget(self.centralwidget)
        self.username_label.setBuddy(self.username_edit)
        self.password_label.setBuddy(self.password_input)

        # Final adjustments:
        self.retranslate_ui()
        self.connect_slots_and_signals()

        self.tab_widget.setCurrentIndex(0)

    def connect_slots_and_signals(self):
        QtCore.QObject.connect(self.cancel_button_1, QtCore.SIGNAL(_fromUtf8("clicked()")), self.close)
        QtCore.QObject.connect(self.cancel_button_2, QtCore.SIGNAL(_fromUtf8("clicked()")), self.close)
        QtCore.QObject.connect(self.cancel_button_3, QtCore.SIGNAL(_fromUtf8("clicked()")), self.close)
        QtCore.QObject.connect(self.finish_button, QtCore.SIGNAL(_fromUtf8("clicked()")), self.handle_finish_button)
        QtCore.QObject.connect(self.next_button_1, QtCore.SIGNAL(_fromUtf8("clicked()")), self.next_page)
        QtCore.QObject.connect(self.next_button_2, QtCore.SIGNAL(_fromUtf8("clicked()")), self.next_page)
        QtCore.QObject.connect(self.back_button_1, QtCore.SIGNAL(_fromUtf8("clicked()")), self.previous_page)
        QtCore.QObject.connect(self.back_button_2, QtCore.SIGNAL(_fromUtf8("clicked()")), self.previous_page)

        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslate_ui(self):
        self.setWindowTitle(_translate("MainWindow", "Bulldog- Encrypt", None))
        self.file_selection_label.setText(_translate("MainWindow", FILE_CHOOSING_TAB_TEXT, None))
        self.file_selection_label.setStyleSheet(_fromUtf8(GREY_BACKGROUND))

        self.cancel_button_1.setText(_translate("MainWindow", "Cancel", None))
        self.next_button_1.setText(_translate("MainWindow", "Next", None))
        self.tab_widget.setTabText(self.tab_widget.indexOf(self.file_selection), _translate("MainWindow", "Step 1", None))
        self.encryption_label.setText(_translate("MainWindow", ENCRYPTION_TAB_TEXT, None))
        self.encryption_label.setStyleSheet(_fromUtf8(GREY_BACKGROUND))
        self.AES_button.setText(_translate("MainWindow", AES_EXPLANATION, None))
        self.blowfish_button.setText(_translate("MainWindow", BLOWFISH_EXPLANATION, None))
        self.TDES_button.setText(_translate("MainWindow", TDES_EXPLANATION, None))
        self.back_button_1.setText(_translate("MainWindow", "Back", None))
        self.cancel_button_2.setText(_translate("MainWindow", "Cancel", None))
        self.next_button_2.setText(_translate("MainWindow", "Next", None))
        self.tab_widget.setTabText(self.tab_widget.indexOf(self.encryption_selection), _translate("MainWindow",
                                                                                                  "Step 2", None))
        self.auth_label.setText(_translate("MainWindow", AUTHENTICATION_TEXT, None))
        self.auth_label.setStyleSheet(_fromUtf8(GREY_BACKGROUND))
        self.username_label.setText(_translate("MainWindow", "Username:", None))
        self.username_label.setStyleSheet(_fromUtf8(GREY_BACKGROUND))
        self.password_label.setText(_translate("MainWindow", "Password:", None))
        self.password_label.setStyleSheet(_fromUtf8(GREY_BACKGROUND))
        self.back_button_2.setText(_translate("MainWindow", "Back", None))
        self.cancel_button_3.setText(_translate("MainWindow", "Cancel", None))
        self.finish_button.setText(_translate("MainWindow", "Finish", None))
        self.tab_widget.setTabText(self.tab_widget.indexOf(self.authentication),
                                   _translate("MainWindow", "Step 3", None))

    def next_page(self):
        if self.tab_widget.currentIndex() == 1:
            if self.AES_button.isChecked() or self.TDES_button.isChecked() or self.blowfish_button.isChecked():
                self.tab_widget.setCurrentIndex(self.tab_widget.currentIndex() + 1)
            else:
                # TODO: Can't go to next page popup here
                pass
        else:
            self.tab_widget.setCurrentIndex(self.tab_widget.currentIndex() + 1)

    def previous_page(self):
        self.tab_widget.setCurrentIndex(self.tab_widget.currentIndex() - 1)

    def handle_finish_button(self):
        if len(self.username_edit.text()) == 0 or len(self.password_input.text()) == 0:
            # TODO: 'Please enter username and password' popup
            return
        else:
            encryption_method = 0
            if self.AES_button.isChecked():
                encryption_method = MODE_AES
            elif self.blowfish_button.isChecked():
                encryption_method = MODE_BLOWFISH
            self.task = Task(encryption_method, self.username_edit.text(), self.password_input.text(), self.selected_path)
            self.close()


import _gui_root


def main():
    """
    The main function of the program.
    :return: None
    """
    app = QtGui.QApplication(sys.argv)

    window = EncryptionWindow(sys.argv[1])
    window.show()

    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
