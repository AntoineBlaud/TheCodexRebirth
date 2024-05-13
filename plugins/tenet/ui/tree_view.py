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


class GraphItem:
    def __init__(self, start, end, name, idx):
        self.start = start
        self.end = end
        self.name = name
        self.start_idx = idx
        self.end_idx = 0
        self.childrens = []
        self.parent = None

    def set_end_idx(self, idx):
        self.end_idx = idx


class CallGraph:
    def __init__(self):
        self.root = None


class MyTreeView(QTreeView):
    def __init__(self, parent=None):
        super(MyTreeView, self).__init__(parent=parent)
        self.clicked.connect(self.on_clicked)
        self.reader = None

    def set_reader(self, reader):
        self.reader = reader

    def on_clicked(self, index):
        self.reader.seek(self.model().itemFromIndex(index).idx)

    def filter_size(self, size, clear=False):
        if clear:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,255)}")
        else:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,220)}")
        if size:
            for row in range(self.model().rowCount()):
                item = self.model().item(row)
                if item.f_size < int(size):
                    self.setRowHidden(row, QModelIndex(), True)
                    item.visible = False
                else:
                    self.setRowHidden(row, QModelIndex(), False)
                    item.visible = True

    def filter(self, pattern, positive=True, clear=False):
        if clear:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,255)}")
        else:
            self.setStyleSheet("QTreeView{background-color:rgb(255,255,220)}")

        def recurow(s, selfrow):
            isvisible = False
            if s.visible or clear:
                for row in range(s.rowCount()):
                    item = s.child(row)
                    childvisible = recurow(item, row)
                    if positive:
                        isvisible = isvisible or childvisible
                parent = s.parent()
                if parent:
                    parent = parent.index()
                    if clear:
                        self.setRowHidden(selfrow, parent, False)
                        s.visible = True
                    else:
                        if bool(re.search(pattern, str(s.text()))) == positive:
                            isvisible = True
                        if not isvisible:
                            self.setRowHidden(selfrow, parent, True)
                            s.visible = False

            return isvisible

        for row in range(self.model().rowCount()):
            recurow(self.model().item(row), row)


class CallTreeView(QWidget):
    def __init__(self, callgraph, reader, parent):
        super(CallTreeView, self).__init__()
        self.tree = MyTreeView(self)
        self.tree.setIndentation(10)
        self.parent = parent
        self.searchable_memory = parent.reader.trace.searchable_memory
        layout = QVBoxLayout(self)
        layout.addWidget(self.tree)
        self.reset_callgraph(callgraph, reader)
        self.init_ctx_menu()
        self.idx = 0

    def reset_callgraph(self, callgraph, reader):
        self.all_items = [None for i in range(reader.trace.length)]
        self.all_items_graph = [None for i in range(reader.trace.length)]

        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["Functions"])
        self.tree.set_reader(reader)
        self.tree.header().setDefaultSectionSize(180)
        self.tree.setModel(self.model)
        self.tree.setAutoExpandDelay(0)
        self.import_data(callgraph)
        self.tree.expandAll()
        header = self.tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(False)
        reader.idx_changed(self.scrolld)

    def depth_color(self, depth):
        r = 255 - 14 * abs(depth % 12 - 6)
        g = 255 - 14 * abs((depth + 4) % 12 - 6)
        b = 255 - 14 * abs((depth + 8) % 12 - 6)
        return r, g, b

    def append_found_strings(self, qitem_str, detected_strings):
        # Append the strings detected in the function
        qitem_str += " [ "
        if detected_strings:
            offset = 0
            max_len = 100
            max_lines = 2
            i = 0
            # Consider only the first 20 strings
            first_20_strings = ", ".join(detected_strings[:20])
            while offset + max_len < len(first_20_strings) and i < max_lines:
                # Construct the qitem_str with strings on multiple lines
                qitem_str += first_20_strings[offset : offset + max_len] + "\n    "
                offset += max_len
                i += 1
            qitem_str += first_20_strings[offset:]
            if len(detected_strings) > 20:
                qitem_str += "..."

        qitem_str += " ]"
        return qitem_str

    def recurparse(self, parent_view_item, node_item, depth=0):

        qitem_str = node_item.name + " (%d - %d) " % (node_item.start_idx, node_item.end_idx)
        detected_strings = self.searchable_memory.get_strings_inside_idx_range(node_item.start_idx, node_item.end_idx)

        qitem_str = self.append_found_strings(qitem_str, detected_strings)

        qitem = QStandardItem(qitem_str)
        qitem.idx = node_item.start_idx
        qitem.visible = True
        r, g, b = self.depth_color(depth)
        qitem.setBackground(QBrush(QColor(r, g, b)))

        if len(node_item.childrens):
            qitem.has_childrens = True
        else:
            qitem.has_childrens = False

        self.all_items[qitem.idx] = qitem
        self.all_items_graph[qitem.idx] = node_item
        qitem.setEditable(False)
        parent_view_item.appendRow([qitem])

        for child_graph_item in node_item.childrens:
            self.recurparse(parent_view_item.child(parent_view_item.rowCount() - 1), child_graph_item, depth + 1)

    def import_data(self, callgraph, root_view=None):
        self.model.setRowCount(0)
        root_view = self.model.invisibleRootItem() if root_view is None else root_view
        self.rootcg = callgraph.root

        self.recurparse(root_view, self.rootcg)

        for items in [self.all_items, self.all_items_graph]:
            current_item = items[0]
            for i, item in enumerate(items):
                if item:
                    current_item = item
                else:
                    items[i] = current_item

    def adjust_scrollbar(self):
        self.tree.scrollTo(self.tree.currentIndex(), QTreeView.PositionAtCenter)
        # compute the horizontal scroll bar position to center the current item
        rect = self.tree.visualRect(self.tree.currentIndex())
        first_rect = self.tree.visualRect(self.all_items[0].index())
        # Adjust the scrollbar to center the current item
        rect_x = rect.x()
        if first_rect.x() < 0:
            rect_x = rect_x + abs(first_rect.x())
        self.tree.horizontalScrollBar().setMinimum(0)
        # get scrolling range
        max_scroll = self.tree.horizontalScrollBar().maximum()
        # make a ratio
        ratio = max_scroll / (rect_x + rect.width() - 120)
        # set the value
        self.tree.horizontalScrollBar().setValue(rect_x * ratio)
        # print(f"rect_x: {rect_x}, max_scroll: {max_scroll}, ratio: {ratio}, rect.x(): {rect.x()}, first_rect.x(): {first_rect.x()}")

    def scrolld(self, idx):
        try:
            self.tree.setCurrentIndex(self.all_items[idx].index())
            self.idx = idx
            self.adjust_scrollbar()
        except AttributeError as e:
            print(e)

    def action_filter(self):
        bst = ida_kernwin.ask_str("", 6748, "Prepend with ! to invert a filter\nFilter is a regex")
        if bst:
            for st in bst.split("&&"):
                positive = True
                if "!" == st[0]:
                    positive = False
                    st = st[1:]
                self.tree.filter(st, positive)

    def action_filter_size(self):
        bst = ida_kernwin.ask_str("", 6748, " Give the minimum size of the function")
        self.tree.filter_size(bst)

    def init_ctx_menu(self):
        """
        Initialize the right click context menu actions.
        """
        self.menu = QMenu()

        # create actions to show in the context menu
        self.action_collapse = self.menu.addAction("Collapse all but selection")
        self.action_expand = self.menu.addAction("Expand all")
        self.reload = self.menu.addAction("Reload function names")
        self._action_filter_size = self.menu.addAction("Filter Size")
        self._action_filter = self.menu.addAction("Filter")
        self._action_clearfilter = self.menu.addAction("Clear filters")
        self.action_parent = self.menu.addAction("Parent")

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
            self.tree.filter("", clear=True)
        elif action == self._action_filter_size:
            self.action_filter_size()
            # Navigate to the parent function
        elif action == self.action_parent:
            parent_idx = self.all_items_graph[self.idx].parent.start_idx
            self.scrolld(parent_idx)


class TreeDock:

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
            elif func.start_ea == addr:
                nam = idaapi.get_ea_name(addr, idaapi.GN_DEMANGLED)
                if nam:
                    nam = nam.split("(")[0]
                    nam.rstrip("<")
                    suffix = 2
                    bnam = nam
                    if not nam in self.funcs_idx:
                        self.funcs_idx[nam] = 1
                    else:
                        self.funcs_idx[nam] += 1
                        nam = nam + "/" + str(self.funcs_idx[nam])

                    self.funcs_ival[nam] = (func.start_ea, func.end_ea)
            self.funcs_start[addr] = nam
        return self.funcs_start[addr]

    def reload(self):
        self.compute_callgraph()
        if self.view:
            self.view.reset_callgraph(self.callgraph, self.reader)

    def compute_callgraph(self):
        reader = self.reader

        def get_func_info(pc):
            func_start = idc.get_func_attr(pc, idc.FUNCATTR_START)
            func_end = idc.get_func_attr(pc, idc.FUNCATTR_END)
            func_name = idc.get_func_name(func_start)
            if func_name:
                func_name = func_name.split("(")[0]
                func_name.rstrip("<")
            return func_start, func_end, func_name

        pc_start = reader.get_ip(0)
        func_start, func_end, func_name = get_func_info(pc_start)

        self.callgraph = CallGraph()
        root = GraphItem(func_start, func_end, func_name, 0)
        self.callgraph.root = root
        last_node = root

        for idx in range(1, reader.trace.length - 1):
            pc = reader.get_ip(idx)
            is_return = False

            # check if the function at idx is the same as the function at idx-1
            if get_func_info(pc)[0] != last_node.start:

                # fetch the parent function of the last function
                parent = last_node.parent

                # if the function at idx is the same as idx-1 parent function,
                # then we returned
                if parent and get_func_info(pc)[0] == parent.start:
                    last_node.set_end_idx(idx - 1)
                    last_node = parent
                    is_return = True

                # when there is a jump, the function changes but the callstack remains the same ...
                # we check if the current function is in the callstack of the parents
                # so we need complex logic to handle this case
                # obviously, if there is function recursion, the logic will fail
                node_exploration = parent
                max_depth, counter = 50, 0
                temp_node_exploration = []
                if not is_return:
                    while node_exploration != None and node_exploration.parent != node_exploration:
                        if node_exploration.start == get_func_info(pc)[0]:
                            last_node = node_exploration
                            is_return = True
                            for node in temp_node_exploration:
                                node.set_end_idx(idx - 1)
                            break
                        # we limit the exploration to 50 levels up
                        if counter > max_depth:
                            break
                        counter += 1
                        node_exploration = node_exploration.parent
                        temp_node_exploration.append(node_exploration)

                # idx -1 makes a call to a new function
                if not is_return:
                    infos = get_func_info(pc)
                    new_item = GraphItem(infos[0], infos[1], infos[2], idx)
                    new_item.parent = last_node
                    last_node.childrens.append(new_item)
                    last_node = new_item

    def show(self, target=None, position=0):
        """
        Make the window attached to this controller visible.
        """

        # if there is no Qt (eg, our UI framework...) then there is no UI
        if not QT_AVAILABLE:
            return

        # the UI has already been created, and is also visible. nothing to do
        if self.dockable and self.dockable.visible:
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
        elif target or position:
            new_dockable.set_dock_position(target, position)

        # make the dockable/widget visible
        self.dockable = new_dockable
        self.dockable.show()

    def hide(self):
        """
        Hide the window attached to this controller.
        """

        # if there is no view/dockable, then there's nothing to try and hide
        if not (self.view and self.dockable):
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
