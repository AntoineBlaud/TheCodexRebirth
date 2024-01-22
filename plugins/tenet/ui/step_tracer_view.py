from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir
from PyQt5.QtCore import Qt
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
import os 
import tempfile


WIDTH = 800
HEIGHT = 600

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
        watcher_name_input.setFont(QFont('Arial', 6))
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
        self.setMinimumWidth(WIDTH-240)
        self.setMinimumHeight(HEIGHT/15)
        self.setMaximumHeight(HEIGHT/15)
        self.setMaximumWidth(WIDTH-240)
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
        watcher_index.setFont(QFont('Arial', 10))
        self.horizontalLayout.addWidget(watcher_index)
        
        self.create_watcher_input("Address : ", "", self.light_grey)
        
        # add the saved value label
        self.saved_value_label = QtWidgets.QLabel(self)
        self.saved_value_label.setText("")
        self.saved_value_label.setAlignment(Qt.AlignCenter)
        self.saved_value_label.setMaximumWidth(int(WIDTH*0.43))
        self.saved_value_label.setMinimumWidth(int(WIDTH*0.43))
        self.saved_value_label.setFont(QFont('Arial', 8))
        self.saved_value_label.setMaximumHeight(30)
        self.saved_value_label.setMinimumHeight(30)
        
        self.horizontalLayout.addWidget(self.saved_value_label)
    
        # add load button
        self.load_button = QtWidgets.QPushButton("Load", self)
        self.load_button.clicked.connect(self._load)
        self.horizontalLayout.addWidget(self.load_button)
        # set button font
        self.load_button.setFont(QFont('Arial', 10))
        self.load_button.setFixedWidth(80)
        # set the background color
        self.setAutoFillBackground(True)
        self.set_not_saved()
        
        
    def _load(self):
        file_path = self.saved_value_label.text()
        file_path = file_path.replace("$TEMP", tempfile.gettempdir())
        # check if the file exist
        if os.path.isfile(file_path):
            self.parentw.pctx.load_trace(file_path)
            self.parentw.pctx.show_ui()
            
    
    def set_saved(self, path):
        path = path.replace(tempfile.gettempdir(), "$TEMP")
        self.saved_value_label.setText(path)
        self.saved_value_label.setStyleSheet(
            "background-color: #4CAF50;"  # Set background color to green
            "color: white;"               # Set text color to white
        )
      
        
    def set_not_saved(self):
        self.saved_value_label.setText("Not Saved")
        self.saved_value_label.setStyleSheet(
            "background-color: #db1a4b;"  # Set background color to green
            "color: white;"               # Set text color to white
        )

class StepTracerView(QMainWindow):
    
    def __init__(self, controller, model, parent=None):
        super(StepTracerView, self).__init__(parent)
        self.controller = controller
        self.pctx = controller.pctx
        self.model = model
        self._init_ui()
        # set windows always on top
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint)
        # set position to the center
        # get screen size
        height = QApplication.desktop().screenGeometry().height()
        width = QApplication.desktop().screenGeometry().width()
        self.move(width - WIDTH - 30, 20)
        
        
    def create_options_input(self, label_text, input_text):
        label = QtWidgets.QLabel(self)
        label.setText(label_text)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(QFont('Arial', 10))
        label.setStyleSheet(
            "background-color: #edebeb;"
            "color: black;"               # Set text color to white
            "padding: 10px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        inputa = QtWidgets.QLineEdit(self)
        inputa.setText(input_text)
        inputa.setAlignment(Qt.AlignCenter)
        inputa.setFont(QFont('Arial', 10))
        inputa.setStyleSheet(
            "background-color: #edebeb;"
            "color: red;"               # Set text color to white
            "padding: 2px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        self.group_box_layout.addWidget(label)
        self.group_box_layout.addWidget(inputa)
        

    def _init_ui(self):

        # child widgets
        self.setWindowTitle("Step Tracer")
        
        #create splitter layout
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
        
        # add windows max size
        self.setFixedHeight(HEIGHT)
        self.setFixedWidth(WIDTH)
        
        self.label2 = QtWidgets.QLabel(self)
        self.label2.setText("Configuration Options")
        self.label2.setAlignment(Qt.AlignCenter)
        self.label2.setFont(QFont('Arial', 11))

        # Add styles to improve appearance
        self.label2.setStyleSheet(
            "background-color: #bfbfbf;"  # Set background color to green
            "color: white;"               # Set text color to white
            "padding: 10px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        self.left_layout.setAlignment(Qt.AlignTop)
        self.left_layout.addWidget(self.label2)
        self.right_layout.setAlignment(Qt.AlignTop)
        
    
        # add Check Box for enable/disable
        self.dynamic_shellcode = QtWidgets.QCheckBox("Dynamic Code (slow)", self)
        self.dynamic_shellcode.setChecked(True)
        self.dynamic_shellcode.setFont(QFont('Arial', 8))
        self.dynamic_shellcode.setStyleSheet(
            "background-color: #edebeb;"
            "color: black;"               # Set text color to white
            "padding: 5px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
    
        # create the group box for the run timeout, dump size and max step inside loop
        self.group_box = QtWidgets.QGroupBox("")
        # create the group box layout
        self.group_box_layout = QtWidgets.QVBoxLayout()
        # set the group box layout
        self.group_box.setLayout(self.group_box_layout)
        # add the group box to the left layout
        self.left_layout.addWidget(self.group_box)
        # set max width for the group box
        self.group_box.setMaximumWidth(WIDTH/4)
        # set max height for the group box
        self.group_box.setMaximumHeight(300)
        # group option attached to the top absolute position
        self.group_box_layout.setAlignment(Qt.AlignTop)
        # add the run timeout, dump size and max step inside loop to the group box
        self.group_box_layout.addWidget(self.dynamic_shellcode)
        self.create_options_input("Run Timeout",  str(self.model.runTimeout))
        self.create_options_input("Dump Size", str(self.model.dumpSize))
        self.create_options_input("Max Step Inside Loop", str(self.model.maxStepInsideLoop))
        
        bLayout = QHBoxLayout()
        buttonsWidgets = QWidget()
        buttonsWidgets.setLayout(bLayout)
        bLayout.setAlignment(Qt.AlignCenter)
        # add the start button
        self.start_button = QtWidgets.QPushButton("Start", self)
        self.start_button.setFont(QFont('Arial', 10))
        self.start_button.setAutoFillBackground(True)
        self.start_button.setStyleSheet("""
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
        # add delete watcher button
        self.delete_watcher_button = QtWidgets.QPushButton("Clear Watcher", self)
        self.delete_watcher_button.setFont(QFont('Arial', 10))
        self.delete_watcher_button.setAutoFillBackground(True)
        self.delete_watcher_button.clicked.connect(self.delete_watcher)
        bLayout.addWidget(self.delete_watcher_button)
        
        
        # add label
        self.label = QtWidgets.QLabel(self)
        self.label.setText("Watchers Configuration")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setFont(QFont('Arial', 11))
        self.label.setStyleSheet(
            "background-color: #bfbfbf;"  # Set background color to green
            "color: white;"               # Set text color to white
            "padding: 10px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        self.right_layout.addWidget(self.label)
        
        # add extendable list view on the right layout
        self.extendable_list_view = QWidget(self)
        self.extendable_list_view_layout = QVBoxLayout()
        self.right_layout.addWidget(self.extendable_list_view)
        self.extendable_list_view.setLayout(self.extendable_list_view_layout)
        # set max width for the extendable list view
        self.extendable_list_view.setFixedWidth(WIDTH)
        # set max height for the extendable list view
        self.extendable_list_view.setFixedHeight(HEIGHT - 100)
        # item start at the top left corner
        self.extendable_list_view_layout.setAlignment(Qt.AlignTop)
        # set the background color for the extendable list view
        self.extendable_list_view.setStyleSheet("background-color: rgb(255, 255, 255);")
        
        
        # add a progress bar
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%")
        # set progress bar at the bottom
        self.progress_bar.setAlignment(Qt.AlignBottom)
        
        # add the progress bar to the right layout
        self.left_layout.addWidget(self.progress_bar)
        
        self.left_layout.addWidget(self.start_button)
        # add the add watcher button
        self.right_layout.addWidget(buttonsWidgets)
        self.watcher_size = 0
        self.total_watcher = 12
        for i in range(self.total_watcher):
            self.add_watcher()
    
    
    def add_watcher(self):
        if self.watcher_size < self.total_watcher :
            watcher_widget = WatcherWidget(self, index=self.watcher_size)
            watcher_widget.setAutoFillBackground(True)
            self.extendable_list_view.layout().addWidget(watcher_widget)
            self.watcher_size += 1
            
    def delete_watcher(self):
        # ask the user for the watcher index
        text, ok = QInputDialog.getText(self, 'Delete Watcher', 'Enter the watcher index:')
        if ok:
            try:
                index = int(text)
                if index >= 0 and index < self.watcher_size:
                    watcher_widget = self.extendable_list_view.layout().itemAt(index).widget()
                    # delte it now
                    watcher_widget.setParent(None)
                    # if exist in model remove it
                    if len(self.model.watchers) > index:
                        self.model.watchers.pop(index)
                    self.watcher_size -= 1
                    # update index for all watchers
                    for i in range(self.watcher_size):
                        watcher_widget = self.extendable_list_view.layout().itemAt(i).widget()
                        watcher_widget.index = i
                        watcher_widget.layout().itemAt(0).widget().setText(str(i))
                    self.add_watcher()
            except Exception as e:
                print(e)
                pass
        
            
    def _refresh(self):

        # refresh the watcher list 
        length_model = len(self.model.watchers)
        length_ui = self.extendable_list_view.layout().count()
        for i in range(length_model):
            watcher_widget = self.extendable_list_view.layout().itemAt(i).widget()
            watcher_address_input = watcher_widget.horizontalLayout.itemAt(1).widget()
            watcher_address_input.setText(hex(self.model.watchers[i].address))
            if self.model.watchers[i].is_saved:
                watcher_widget.set_saved(self.model.watchers[i].path)
                
        for i in range(length_model, length_ui):
            watcher_widget = self.extendable_list_view.layout().itemAt(i).widget()
            watcher_address_input = watcher_widget.horizontalLayout.itemAt(1).widget()
            addr = 0x0
            try:
                addr = int(watcher_address_input.text(), 16)
                self.model.add_watcher(addr)
            except:
                pass
            
                    
    def _start(self):
        self._refresh()
        # fetch options
        self.model.isDynamicShellcode = self.dynamic_shellcode.isChecked()
        self.model.runTimeout = int(self.group_box_layout.itemAt(2).widget().text())
        self.model.dumpSize = int(self.group_box_layout.itemAt(4).widget().text())
        self.model.maxStepInsideLoop = int(self.group_box_layout.itemAt(6).widget().text())
        self.controller.run()
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
   
   

# class Watcher:
#     def __init__(self, address):
#         self.address = address
#         self.is_saved = False
#         self.path = None


# class StepTracerModel:
#     def __init__(self, pctx):
#         self.pctx = pctx
#         self.isDynamicShellcode = True
#         self.runTimeout = 20
#         self.resetSegmentInc = 20
#         self.dumpSize = 10
#         self.maxStepInsideLoop = 2
#         self.watchers = []
#         self.functionBreakpoints = {}
#         self.loopAlreadySkipped = {}
#         self.currentJumps = {}
#         self.loopCounts = {}
#         self.breakpoints = {}
#         self.seenInstructionsCount = {}
#         self.tempDataBuffer = {}
#         self.tenetTrace = []
        
        
#     def add_watcher(self, address):
#         self.watchers.append(Watcher(address))
        
#     def update_watcher(self, index,address):
#         w = self.watchers[index]
#         w.address = address
        
#     def on_watcher(self, ea):
#         for w in self.watchers:
#             if w.address == ea:
#                 return w
        
        
        
        
# # # creat the main window
# app = QApplication([])
# # create the controller
# controller = None
# # create the model
# model = StepTracerModel(None)
# # create the view
# view = StepTracerView(controller, model)
# model.add_watcher(0x43)
# view._refresh()
# # show the view
# view.show()
# # start the application
# app.exec_()
