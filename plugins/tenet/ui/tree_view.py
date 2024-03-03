import idautils
import idaapi
import idc
import re
import sys
import ida_kernwin

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from tenet.util.qt import QT_AVAILABLE
from tenet.integration.api import DockableWindow
# TODO: clean :)
sys.setrecursionlimit(100000)

class MyTreeView(QTreeView):
    def __init__(self, parent=None):
        super(MyTreeView, self).__init__(parent=parent)
        self.clicked.connect(self.on_clicked)
        self.reader = None
        
    def set_reader(self, reader):
        self.reader = reader
    
    def on_clicked(self, index):
        self.reader.seek(self.model().itemFromIndex(index).idx)
        
    def filter_size(self, size):
        if clear:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,255)}")
        else:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,220)}")
        if size:
            for row in range(self.model().rowCount()):
                item = self.model().item(row)
                if item.f_size < int(size):
                    self.setRowHidden(row, QModelIndex(), True)
                    item.visible=False
                else:
                    self.setRowHidden(row, QModelIndex(), False)
                    item.visible=True
    
    def filter(self, pattern, positive=True, clear=False):
        if clear:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,255)}")
        else:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,220)}")
            
        for row in range(self.model().rowCount()):
            item = self.model().item(row)
            if re.search(pattern, item.text(), re.IGNORECASE):
                self.setRowHidden(row, QModelIndex(), False)
                item.visible = positive
            else:
                self.setRowHidden(row, QModelIndex(), True)
                item.visible = not positive
        
        


class CallTreeView(QWidget):
    def __init__(self, callgraph, reader, parent):
        super(CallTreeView, self).__init__()
        self.tree = MyTreeView(self)
        self.tree.setIndentation(10)
        self.parent = parent
        
        layout = QVBoxLayout(self)
        layout.addWidget(self.tree)
        self.reset_callgraph(callgraph, reader)
        self.init_ctx_menu()
    
    def reset_callgraph(self, callgraph, reader):
        self.all_items = [None for i in range(reader.trace.length)]
        
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Functions'])
        self.tree.set_reader(reader)
        self.tree.header().setDefaultSectionSize(180)
        self.tree.setModel(self.model)
        self.tree.setAutoExpandDelay(0)
        self.importData(callgraph)
        self.tree.expandAll()
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(False)
        reader.idx_changed(self.scrolld)

    def name_color(self, string):
        # Initialize RGB values
        r = 0
        g = 0
        b = 0
        
        # Sum up the ASCII values of all characters in the string
        total_ascii = sum(ord(char) for char in string)
        
        # Use modulo to distribute the total ASCII value into RGB channels
        r = (total_ascii * 17) % 200 + 55
        g = (total_ascii * 19) % 200 + 55
        b = (total_ascii * 23) % 200 + 55
        
        return (r, g, b)
        
        
    def parse_item(self, item, p, depth=0):
        if not p:return
        new_item = QStandardItem(p[0])
        new_item.idx = p[1]
        new_item.f_size = p[2]
        new_item.visible = True
        ea = self.parent.reader.get_ip(new_item.idx) + self.parent.reader.analysis.slide
        func = idaapi.get_func(ea)
        if func:
            size = func.end_ea - func.start_ea
        else:
            size = 0
        r,g,b = self.name_color(p[0])
        new_item.setBackground(QBrush(QColor(r,g,b)))

        new_item.has_children = False
        self.all_items[new_item.idx] = new_item
        new_item.setEditable(False)
        item.appendRow([new_item])
        
    def importData(self, callgraph, root=None):
        self.model.setRowCount(0)
        if root is None:
            root = self.model.invisibleRootItem()
        
        if callgraph:
            for e in callgraph:
                self.parse_item(root, e)
        current = self.all_items[0]
        for i in range(len(self.all_items)):
            if self.all_items[i]:
                current = self.all_items[i]
            else: self.all_items[i] = current
    
    def scrolld(self, idx):
        try:
            self.tree.setCurrentIndex(self.all_items[idx].index())
            self.tree.scrollTo(self.tree.currentIndex(), QTreeView.PositionAtCenter)
            self.tree.horizontalScrollBar().setValue(0)
        except AttributeError:
            pass

    def action_filter(self):
        bst = ida_kernwin.ask_str("",6748, "Prepend with ! to invert a filter\nFilter is a regex")
        if bst:
            for st in bst.split("&&"):
                positive = True
                if "!"==st[0]:
                    positive=False
                    st=st[1:]
                self.tree.filter(st,positive)   
                
    def action_filter_size(self):
        bst = ida_kernwin.ask_str("",6748, " Give the minimum size of the function")
        self.tree.filter_size(bst)

    
    def init_ctx_menu(self):
        """
        Initialize the right click context menu actions.
        """
        self.menu = QMenu()

        # create actions to show in the context menu
        self.reload = self.menu.addAction("Reload function names")
        self._action_filter = self.menu.addAction("Filter Name")
        self._action_filter_size = self.menu.addAction("Filter Size")
        self._action_clearfilter = self.menu.addAction("Clear Name filters")
        


        # install the right click context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.ctx_menu_handler)
    

    def ctx_menu_handler(self, position):
        """
        Handle a right click event (populate/show context menu).
        """
        action = self.menu.exec_(self.mapToGlobal(position))
        if action == self.reload:
            self.parent.reload()
        elif action == self._action_filter:
            self.action_filter()
        elif action == self._action_filter_size:
            self.action_filter_size()
        elif action == self._action_clearfilter:
            self.tree.filter("",clear=True)

        
class TreeDock():

    def __init__(self, pctx):
        self.pctx = pctx
        self.reader = None

        # UI components
        self.view = None
        self.dockable = None

        self.funcs_start = None
        self.funcs_ival = None


    def reload(self):
        self.compute_callgraph()
        if self.view:
            self.view.reset_callgraph(self.callgraph, self.reader)

    def compute_callgraph(self):
      
        callgraph = []
        reader = self.reader
        aslr = reader.analysis.slide if reader.analysis.slide else 0
        last_f_name = None
            
        # populate the callgraph
        for idx in range(1, reader.trace.length-1):
            pc = reader.get_ip(idx)
            f_name = idc.get_func_name(pc)
            f_size = idc.get_func_attr(pc, idc.FUNCATTR_END) - idc.get_func_attr(pc, idc.FUNCATTR_START)
            if f_name != last_f_name:
                last_f_name = f_name
                callgraph.append((f_name, idx, f_size))
            
        self.callgraph = callgraph

    def show(self, target=None, position=0):
        """
        Make the window attached to this controller visible.
        """

        # if there is no Qt (eg, our UI framework...) then there is no UI
        if not QT_AVAILABLE:
            return

        # the UI has already been created, and is also visible. nothing to do
        if (self.dockable and self.dockable.visible):
            return

        #
        # if the UI has not yet been created, or has been previously closed
        # then we are free to create new UI elements to take the place of
        # anything that once was
        #

        self.view = CallTreeView(self.callgraph, self.reader, self)
        new_dockable = DockableWindow("Call tree view", self.view)

        #
        # if there is a reference to a left over dockable window (e.g, from a
        # previous close of this window type) steal its dock positon so we can
        # hopefully take the same place as the old one
        #

        if self.dockable:
            new_dockable.copy_dock_position(self.dockable)
        elif (target or position):
            new_dockable.set_dock_position(target, position)

        # make the dockable/widget visible
        self.dockable = new_dockable
        self.dockable.show()

    def hide(self):
        """
        Hide the window attached to this controller.
        """

        # if there is no view/dockable, then there's nothing to try and hide
        if not(self.view and self.dockable):
            return

        # hide the dockable, and drop references to the widgets
        self.dockable.hide()
        self.view = None
        self.dockable = None

    def attach_reader(self, reader):
        """
        Attach a trace reader to this controller.
        """
        self.reader = reader
        self.reload()


    def detach_reader(self):
        """
        Detach the active trace reader from this controller.
        """
        self.reader = None
        self.callgraph = None
        if self.view:
            self.view.reset_callgraph(None, self.reader)
