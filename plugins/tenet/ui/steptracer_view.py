from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir
from PyQt5.QtCore import Qt
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
import os
import tempfile
import time


class WatcherWidget(QWidget):
    def __init__(self, parent=None, index=0):
        super(WatcherWidget, self).__init__(parent)
        self.index = index
        self.parentw = parent

        self._init_ui()

    def create_watcher_input(self, label_text, input_text, color="rgb(255, 255, 255)"):
        # set max width for the watcher name label
        # add input for the watcher name below the watcher name label
        watcher_name_input = QtWidgets.QLineEdit(self)
        watcher_name_input.setText(input_text)
        watcher_name_input.setFixedWidth(60)
        watcher_name_input.setFixedHeight(30)
        watcher_name_input.setAlignment(Qt.AlignCenter)
        watcher_name_input.setFont(QFont("Arial", 6))
        # add update watcher name when the text change
        # set default text
        watcher_name_input.setPlaceholderText("0x0")

        # create a vertical layout var using class dictionary

        # disable all margins for the horizontal layout
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setSpacing(5)
        self.horizontalLayout.setAlignment(Qt.AlignLeft)

        self.horizontalLayout.addWidget(watcher_name_input)
        # remove border for the watcher name input
        watcher_name_input.setStyleSheet("border: 1px solid black;")

    def _init_ui(self):
        self.setStyleSheet("background-color: rgb(255, 255, 255);")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self)
        self.horizontalLayout.setObjectName("horizontalLayout")

        self.red = "rgb(255, 100, 100)"
        self.light_grey = "rgb(200, 200, 200)"

        # add watcher name label
        watcher_index = QtWidgets.QLabel(self)
        watcher_index.setText(str(self.index))
        watcher_index.setFixedWidth(25)
        watcher_index.setFixedHeight(30)
        watcher_index.setFont(QFont("Arial", 10))
        self.horizontalLayout.addWidget(watcher_index)

        self.create_watcher_input("Address : ", "", self.light_grey)

        # add the saved value label
        self.saved_value_label = QtWidgets.QLabel(self)
        self.saved_value_label.setText("")
        self.saved_value_label.setAlignment(Qt.AlignCenter)
        self.saved_value_label.setFont(QFont("Arial", 8))
        self.saved_value_label.setMinimumWidth(200)
        self.saved_value_label.setMinimumHeight(30)

        self.horizontalLayout.addWidget(self.saved_value_label)

        # add load button
        self.load_button = QtWidgets.QPushButton("Load", self)
        self.load_button.clicked.connect(self._load)
        self.horizontalLayout.addWidget(self.load_button)
        # set button font
        self.load_button.setFont(QFont("Arial", 10))
        self.load_button.setFixedWidth(80)
        # set the background color
        self.setAutoFillBackground(True)
        self.set_not_saved()

    def _load(self):
        file_path = self.saved_value_label.text()
        # check if the file exist
        if os.path.isfile(file_path):
            self.parentw.pctx.load_trace(file_path)
            self.parentw.pctx.show_ui()

    def set_saved(self, path):
        path = path.replace(tempfile.gettempdir(), "%TEMP%")
        self.saved_value_label.setText(path)
        self.saved_value_label.setStyleSheet(
            "background-color: #4CAF50;"  # Set background color to green
            "color: white;"  # Set text color to white
        )

    def set_not_saved(self):
        self.saved_value_label.setText("Not Saved")
        self.saved_value_label.setStyleSheet(
            "background-color: #db1a4b;"  # Set background color to green
            "color: white;"  # Set text color to white
        )


class StepTracerView(QMainWindow):

    def __init__(self, controller, model, parent=None):
        super(StepTracerView, self).__init__(parent)
        self.controller = controller
        try:
            self.pctx = controller.pctx
        except:
            self.pctx = None
        self.model = model
        self._init_ui()
        # set windows always on top
        self.setWindowFlags(Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint | Qt.WindowCloseButtonHint | Qt.Window)

        # set position to the center
        # get screen size
        height = QApplication.desktop().screenGeometry().height()
        width = QApplication.desktop().screenGeometry().width()
        self.move(width - 900 - 30, 20)

    def create_options_input(self, label_text, input_text):
        label = QtWidgets.QLabel(self)
        label.setText(label_text + " : ")
        label.setAlignment(Qt.AlignLeft)
        label.setFont(QFont("Arial", 10))
        label.setStyleSheet(
            "background-color: rgba(0, 0, 0,255)"
            "padding: 0px;"  # Add padding around the label
            "color: black;"  # Set text color to white
            "border-radius: 5px;"  # Add rounded corners
        )
        inputa = QtWidgets.QLineEdit(self)
        inputa.setText(input_text)
        inputa.setAlignment(Qt.AlignCenter)
        inputa.setFont(QFont("Arial", 10))
        inputa.setStyleSheet(
            "background-color: #edebeb;"
            "color: red;"  # Set text color to white
            "padding: 2px;"  # Add padding around the label
            "border-radius: 5px;"  # Add rounded corners
        )
        self.group_box_layout.addWidget(label)
        self.group_box_layout.addWidget(inputa)

    def _init_ui(self):

        # child widgets
        self.setWindowTitle("Step Tracer")

        # create splitter layout
        splitter = QtWidgets.QSplitter(self)
        # set the orientation of the splitter
        splitter.setOrientation(Qt.Horizontal)
        # create left layout and widget
        left_widget = QtWidgets.QWidget()
        self.left_layout = QtWidgets.QVBoxLayout()
        left_widget.setLayout(self.left_layout)
        # create right layout
        right_widget = QtWidgets.QWidget()
        self.right_layout = QtWidgets.QVBoxLayout()
        right_widget.setLayout(self.right_layout)
        # add the splitter to the main window
        self.setCentralWidget(splitter)
        # add the left layout to the splitter
        splitter.addWidget(left_widget)
        # add the right layout to the splitter
        splitter.addWidget(right_widget)

        self.label2 = QtWidgets.QLabel(self)
        self.label2.setText("Configuration Options")
        self.label2.setAlignment(Qt.AlignCenter)
        self.label2.setFont(QFont("Arial", 11))

        # Add styles to improve appearance
        self.label2.setStyleSheet(
            "background-color: #bfbfbf;"  # Set background color to green
            "color: white;"  # Set text color to white
            "padding: 10px;"  # Add padding around the label
            "border-radius: 5px;"  # Add rounded corners
        )
        self.left_layout.setAlignment(Qt.AlignTop)
        self.left_layout.addWidget(self.label2)
        self.right_layout.setAlignment(Qt.AlignTop)

        # create the group box for the run timeout, dump size and max step inside loop
        self.group_box = QtWidgets.QGroupBox("")
        # create the group box layout
        self.group_box_layout = QtWidgets.QVBoxLayout()
        # set the group box layout
        self.group_box.setLayout(self.group_box_layout)
        # add the group box to the left layout
        self.left_layout.addWidget(self.group_box)
        # group option attached to the top absolute position
        self.group_box_layout.setAlignment(Qt.AlignTop)
        # add the run timeout, dump size and max step inside loop to the group box

        self.create_options_input("Run Timeout", str(self.model.run_timeout))
        self.create_options_input("Dump Size", str(self.model.dump_size))
        self.create_options_input("Max Step Inside Loop", str(self.model.max_instruction_hits))
        self.create_options_input("Module to Trace", self.model.root_filename)
        self.create_options_input("Stop at Idx", str(self.model.stop_at_idx))
        self.create_options_input("Watchdog Max Hits", str(self.model.watchdog_max_hits))

        bLayout = QHBoxLayout()
        buttonsWidgets = QWidget()
        buttonsWidgets.setLayout(bLayout)
        bLayout.setAlignment(Qt.AlignCenter)
        # add the start button
        self.start_button = QtWidgets.QPushButton("Start", self)
        self.start_button.setFont(QFont("Arial", 10))
        self.start_button.setAutoFillBackground(True)
        self.start_button.setStyleSheet(
            """
        QPushButton {
            background-color: #edebeb;
            color: black;
            border: 1px solid black;
            border-radius: 5px;
        }
        QPushButton:hover {
            background-color: #8d9bf0; 
        }
        """
        )
        self.start_button.clicked.connect(self._start)

        # add label
        self.label = QtWidgets.QLabel(self)
        self.label.setText("Watchers Configuration")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setFont(QFont("Arial", 11))
        self.label.setStyleSheet(
            "background-color: #bfbfbf;"  # Set background color to green
            "color: white;"  # Set text color to white
            "padding: 10px;"  # Add padding around the label
            "border-radius: 5px;"  # Add rounded corners
        )
        self.right_layout.addWidget(self.label)

        # add extendable list view on the right layout
        self.extendable_list_view = QWidget(self)
        self.extendable_list_view_layout = QVBoxLayout()
        self.right_layout.addWidget(self.extendable_list_view)
        self.extendable_list_view.setLayout(self.extendable_list_view_layout)
        # item start at the top left corner
        self.extendable_list_view_layout.setAlignment(Qt.AlignTop)
        # set the background color for the extendable list view
        self.extendable_list_view.setStyleSheet("background-color: rgb(255, 255, 255);")

        watcher_widget = WatcherWidget(self)
        watcher_widget.setAutoFillBackground(True)
        self.extendable_list_view.layout().addWidget(watcher_widget)

        # add a progress bar
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat(" %p%")
        # set progress bar at the bottom
        self.progress_bar.setAlignment(Qt.AlignBottom)
        self.progress_bar.setStyleSheet(
            "color: black;" "border: 1px solid black;" "border-radius: 3px;" "height: 10px;"
        )

        # add the progress bar to the right layout
        self.left_layout.addWidget(self.progress_bar)

        self.left_layout.addWidget(self.start_button)
        # add the add watcher button
        self.right_layout.addWidget(buttonsWidgets)

        # add a info button
        self.info_button = QtWidgets.QPushButton("Info", self)
        self.info_button.setFont(QFont("Arial", 10))
        self.info_button.setAutoFillBackground(True)
        self.info_button.setFixedWidth(50)
        self.info_button.setStyleSheet(
            "QPushButton {"
            "   background-color: #4287f5;"
            "   border-style: outset;"
            "   border-width: 2px;"
            "   border-radius: 10px;"
            "   border-color: beige;"
            "   font: bold 14px;"
            "   color: white;"
            "}"
            "QPushButton:hover {"
            "   background-color: #45a049;"
            "}"
            "QPushButton:pressed {"
            "   background-color: #3c8c40;"
            "}"
        )
        self.info_button.clicked.connect(self.show_info)
        self.left_layout.addWidget(self.info_button)

    def show_info(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Step Tracer")
        msg.setInformativeText(
            "Step Tracer is a dynamic analysis tool that allows you to trace the execution of a program and monitor the changes in memory and registers. It also allows you to set breakpoints on specific memory addresses and functions."
        )
        msg.setWindowTitle("Step Tracer")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def _refresh(self):

        # refresh the watcher list
        length_ui = self.extendable_list_view.layout().count()
        watcher_widget = self.extendable_list_view.layout().itemAt(0).widget()
        watcher_address_input = watcher_widget.horizontalLayout.itemAt(1).widget()
        watcher_address_input.setText(hex(self.model.watcher.address))
        if self.model.watcher.is_saved:
            watcher_widget.set_saved(self.model.watcher.path)

    def _start(self):
        self._refresh()
        self.model.run_timeout = int(self.group_box_layout.itemAt(1).widget().text())
        self.model.dump_size = int(self.group_box_layout.itemAt(3).widget().text())
        self.model.max_instruction_hits = int(self.group_box_layout.itemAt(5).widget().text())
        self.model.moduleToTrace = self.group_box_layout.itemAt(7).widget().text()
        self.model.stop_at_idx =  int(self.group_box_layout.itemAt(9).widget().text())
        self.model.watchdog_max_hits = int(self.group_box_layout.itemAt(11).widget().text())
        self.controller.invoke()

    def update_progress(self, start_time, idx):
        percent = int((time.time() - start_time) * 100 / (self.model.run_timeout + 1))
        step_per_second = idx / (time.time() - start_time)
        # show msg in the progress bar
        self.progress_bar.setFormat(f" %p% - idx={idx} - {step_per_second:.2f} steps/s")
        self.progress_bar.setValue(percent)
