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
    
    def filter(self, pattern, positive=True, clear=False):
        if clear:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,255)}")
        else:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,220)}")
        def recurow(s,selfrow):
            isvisible = False
            if s.visible or clear:
                for row in range(s.rowCount()):
                    item = s.child(row)
                    childvisible = recurow(item,row)
                    if positive:
                        isvisible = isvisible or childvisible
                parent = s.parent()
                if parent:
                    parent = parent.index()
                    if clear:
                        self.setRowHidden(selfrow, parent, False)
                        s.visible=True
                    else:
                        if bool(re.search(pattern,str(s.text()))) == positive:
                            isvisible = True
                        if not isvisible:
                            self.setRowHidden(selfrow, parent, True)
                            s.visible=False

            return isvisible

        for row in range(self.model().rowCount()):
            recurow(self.model().item(row),row)


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

    def depth_color(self,depth):
        r=255-14*abs(depth%12-6)
        g=255-14*abs((depth+4)%12-6)
        b=255-14*abs((depth+8)%12-6)
        return r,g,b
        
    def recurparse(self, item, p, depth=0):
        if not p:return
        new_item = QStandardItem(p[0][0])
        new_item.idx = p[0][1]
        new_item.visible = True
        r,g,b = self.depth_color(depth)
        new_item.setBackground(QBrush(QColor(r,g,b)))

        if len(p[1]):
            new_item.has_children = True
        else:
            new_item.has_children = False

        self.all_items[new_item.idx] = new_item
        new_item.setEditable(False)
        item.appendRow([new_item])
        
        for e in p[1]:
            self.recurparse(item.child(item.rowCount() - 1), e, depth+1)
        
    def importData(self, callgraph, root=None):
        self.model.setRowCount(0)
        if root is None:
            root = self.model.invisibleRootItem()
        
        if callgraph:
            for e in callgraph:
                self.recurparse(root, e)
        current = self.all_items[0]
        for i in range(len(self.all_items)):
            if self.all_items[i]:
                current = self.all_items[i]
            else: self.all_items[i] = current
    
    def scrolld(self, idx):
        self.tree.setCurrentIndex(self.all_items[idx].index())
        self.tree.scrollTo(self.tree.currentIndex(), QTreeView.PositionAtCenter)
        self.tree.horizontalScrollBar().setValue(0)

    def action_filter(self):
        bst = ida_kernwin.ask_str("",6748, "Prepend with ! to invert a filter\nFilter is a regex")
        if bst:
            for st in bst.split("&&"):
                positive = True
                if "!"==st[0]:
                    positive=False
                    st=st[1:]
                self.tree.filter(st,positive)   

    
    def init_ctx_menu(self):
        """
        Initialize the right click context menu actions.
        """
        self.menu = QMenu()

        # create actions to show in the context menu
        self.action_collapse = self.menu.addAction("Collapse all but selection")
        self.action_expand = self.menu.addAction("Expand all")
        self.reload = self.menu.addAction("Reload function names")
        self._action_filter = self.menu.addAction("Filter")
        self._action_clearfilter = self.menu.addAction("Clear filters")


        # install the right click context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.ctx_menu_handler)
    

    def ctx_menu_handler(self, position):
        """
        Handle a right click event (populate/show context menu).
        """
        action = self.menu.exec_(self.mapToGlobal(position))
        if action == self.action_expand:
            self.tree.expandAll()
        elif action == self.action_collapse:
            self.tree.collapseAll()
            self.tree.scrollTo(self.tree.currentIndex(), QTreeView.PositionAtCenter)
        elif action == self.reload:
            self.parent.reload()
        elif action == self._action_filter:
            self.action_filter()
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

    def get_func_name(self, addr):
        if not addr in self.funcs_start:
            nam = None
            func = idaapi.get_fchunk(addr)
            if not func:
                nam = -1
            elif func.start_ea==addr:
                nam = idaapi.get_ea_name(addr, idaapi.GN_DEMANGLED)
                if nam:
                    nam = nam.split("(")[0]
                    nam.rstrip("<")
                    suffix = 2
                    bnam = nam
                    if not nam in self.funcs_idx:
                        self.funcs_idx[nam] = 1
                    else:
                        self.funcs_idx[nam]+=1
                        nam = nam+"/"+str(self.funcs_idx[nam])
                    
                    self.funcs_ival[nam] = (func.start_ea, func.end_ea)
            self.funcs_start[addr] = nam
        return self.funcs_start[addr]

    def reload(self):
        self.compute_callgraph()
        if self.view:
            self.view.reset_callgraph(self.callgraph, self.reader)

    def compute_callgraph(self):
        self.funcs_start = {}
        self.funcs_ival = {}
        self.funcs_idx = {}

        funcs_start = self.funcs_start
        funcs_ival = self.funcs_ival
        funcs_idx = self.funcs_idx
        reader = self.reader

        BACKTRACE_TOP = "*!__TOP__!*"
        backtrace = [BACKTRACE_TOP]
        funcs_ival[BACKTRACE_TOP] = (-1,-1)

        callgraph = ((backtrace[0],0), [], None)
        callgraph_current = callgraph

        aslr = reader.analysis.slide if reader.analysis.slide else 0

        minaddr = idc.get_inf_attr(idc.INF_MIN_EA)
        maxaddr = idc.get_inf_attr(idc.INF_MAX_EA)
        start = 0
        external = True
        start_i=0
        while external:
            start=reader.get_ip(start_i)-aslr
            external = not (minaddr <= start <= maxaddr)
            start = reader.get_ip(start_i)-aslr
            start_i+=1
            if start_i==reader.trace.length-1:break

        func_addr = idc.get_func_attr(start, idc.FUNCATTR_START)
        if func_addr and func_addr != start:
            nam = self.get_func_name(func_addr)
            if nam and nam != -1:
                callgraph_current[1].append(((nam,0),[],callgraph_current))
                callgraph_current = callgraph_current[1][-1]
                backtrace.append(nam)
        
        def recurinside(pc):
            for fnam in backtrace:
                ival = funcs_ival[fnam]
                if ival[0] <= pc < ival[1]:
                    return True
            return False

        for i in range(start_i, reader.trace.length-1):
            pc = reader.get_ip(i)-aslr
            npc = reader.get_ip(i+1)-aslr

            ival = funcs_ival[backtrace[-1]]
            inside = ival[0] <= pc < ival[1]
            if (not pc in funcs_start or not funcs_start[pc]) and inside:
                continue
            gfn = self.get_func_name(pc)
            if gfn:
                if gfn == -1:
                    continue
                nam = funcs_start[pc]
                callgraph_current[1].append(((nam,i),[],callgraph_current))
                callgraph_current = callgraph_current[1][-1]
                backtrace.append(nam)
            elif not self.get_func_name(npc) or abs(idc.next_head(pc)-npc)<2 or recurinside(pc):
            #else:
                ival = funcs_ival[backtrace[-1]]
                while not inside:
                    if len(backtrace)==1:break
                    try:
                        backtrace.pop(-1)
                        callgraph_current = callgraph_current[2]
                        ival = funcs_ival[backtrace[-1]]
                    except:
                        print("Error in Tree View at "+str(i))
                    inside = ival[0] <= pc < ival[1]

        self.callgraph = callgraph[1]

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
