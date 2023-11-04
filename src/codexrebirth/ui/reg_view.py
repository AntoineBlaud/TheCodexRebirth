import collections

from ..tools.qt import *
from ..integration.api import disassembler


class RegisterView(QtWidgets.QWidget):
    """
    A container for the the widgets that make up the Registers view.
    """

    def __init__(self, controller, model, parent=None):
        super(RegisterView, self).__init__(parent)
        self.controller = controller
        self.model = model
        self._init_ui()

    def _init_ui(self):
        # child widgets
        self.reg_area = RegisterArea(self.controller, self.model, self)
        self.idx_shell = TimestampShell(self.controller, self.model, self)
        self.setMinimumWidth(self.reg_area.minimumWidth())

        # layout
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.reg_area)
        layout.addWidget(self.idx_shell)
        self.setLayout(layout)

    def refresh(self):
        self.reg_area.refresh()
        self.idx_shell.update()


class TimestampShell(QtWidgets.QWidget):
    def __init__(self, controller, model, parent=None):
        super(TimestampShell, self).__init__(parent)
        self.model = model
        self.controller = controller
        self._init_ui()

    def _init_ui(self):
        # child widgets
        self.head = QtWidgets.QLabel("Position", self)
        self.shell = TimestampLine(self.model, self.controller, self)

        # events
        self.model.registers_changed(self.refresh)

        # layout
        layout = QtWidgets.QHBoxLayout(self)
        # layout.setContentsMargins(5, 0, 5, 0)
        layout.setContentsMargins(5, 0, 0, 5)
        layout.addWidget(self.head)
        layout.addWidget(self.shell)

    def refresh(self):
        self.shell.setText(f"{self.model.idx:,}")


class TimestampLine(QtWidgets.QLineEdit):
    def __init__(self, model, controller, parent=None):
        super(TimestampLine, self).__init__(parent)
        self.model = model
        self.controller = controller
        self._init_ui()

    def _init_ui(self):
        self.setStyleSheet(
            f"""
            QLineEdit {{
                background-color: {self.controller.pctx.palette.reg_bg.name()};
                color: {self.controller.pctx.palette.reg_value_fg.name()};
            }}
            """
        )
        self.returnPressed.connect(self._evaluate)

    def _evaluate(self):
        self.controller.evaluate_expression(self.text())


class RegisterArea(QtWidgets.QAbstractScrollArea):
    """
    A Qt-based CPU register view.
    """

    def __init__(self, controller, model, parent=None):
        super(RegisterArea, self).__init__(parent)
        self.pctx = controller.pctx
        self.controller = controller
        self.model = model

        font = QtGui.QFont("Courier", pointSize=normalize_font(10))
        font.setStyleHint(QtGui.QFont.TypeWriter)
        self.setFont(font)

        fm = QtGui.QFontMetricsF(font)
        self._char_width = fm.width("9")
        self._char_height = fm.height()

        # default to fit roughly 50
        self._default_width = self._char_width * (self.pctx.arch.POINTER_SIZE * 2 + 8)

        # register drawing information
        self._reg_pos = (self._char_width, self._char_height)
        self._reg_fields = {}
        self._hovered_arrow = None

        self.setFocusPolicy(QtCore.Qt.StrongFocus)
        self.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
        self.setMinimumWidth(self._reg_pos[0] + self._default_width)
        self.setMouseTracking(True)

        self._init_reg_positions()
        self._init_ctx_menu()

        self.model.registers_changed(self.refresh)

    def sizeHint(self):
        width = self._default_width
        height = (
            len(self._reg_fields) + 2
        ) * self._char_height  # +2 for line break before IP, and after IP
        return QtCore.QSize(width, height)

    def _init_ctx_menu(self):
        """
        Initialize the right click context menu actions.
        """

        # create actions to show in the context menu
        self._action_copy_value = QtWidgets.QAction("Copy value", None)
        self._action_follow_in_dump = QtWidgets.QAction("Follow in dump", None)
        self._action_follow_in_disassembly = QtWidgets.QAction(
            "Follow in disassembler", None
        )

        # install the right click context menu
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu_handler)

    def _init_reg_positions(self):
        """
        Initialize register positions in the window.
        """
        regs = self.model.arch.REGISTERS
        name_x, y = self._reg_pos

        # find the most common length of a register name
        reg_char_counts = collections.Counter([len(x) for x in regs])
        common_count, _ = reg_char_counts.most_common(1)[0]

        # compute rects for the average reg labels and values
        fm = QtGui.QFontMetricsF(self.font())
        name_size = fm.boundingRect("X" * common_count).size()
        value_size = fm.boundingRect("0" * (self.model.arch.POINTER_SIZE * 2)).size()
        arrow_size = (int(value_size.height() * 0.70) & 0xFE) + 1

        # pre-compute the position of each register in the window
        for reg_name in regs:
            # kind of dirty, but this will push IP a bit further away from the
            # rest of the registers (it should be the last defined one...)
            if reg_name == self.model.arch.IP:
                y += self._char_height

            name_rect = QtCore.QRect(0, 0, name_size.width(), name_size.height())
            name_rect.moveBottomLeft(QtCore.QPoint(name_x, y))

            prev_rect = QtCore.QRect(0, 0, arrow_size, arrow_size)
            next_rect = QtCore.QRect(0, 0, arrow_size, arrow_size)
            arrow_rects = [prev_rect, next_rect]

            prev_x = name_x + name_size.width() + self._char_width
            prev_rect.moveCenter(name_rect.center())
            prev_rect.moveLeft(prev_x)

            value_x = prev_x + prev_rect.width() + self._char_width
            value_rect = QtCore.QRect(0, 0, value_size.width(), value_size.height())
            value_rect.moveBottomLeft(QtCore.QPoint(value_x, y))

            next_x = value_x + value_size.width() + self._char_width
            next_rect.moveCenter(name_rect.center())
            next_rect.moveLeft(next_x)

            # save the register shapes
            self._reg_fields[reg_name] = RegisterField(
                reg_name, name_rect, value_rect, arrow_rects
            )

            # increment y (to the next line)
            y += self._char_height

    def _ctx_menu_handler(self, position):
        """
        Handle a right click event (populate/show context menu).
        """
        menu = QtWidgets.QMenu()

        # if a register was right clicked, fetch its name
        reg_name = self._pos_to_reg(position)
        if reg_name:
            #
            # fetch the disassembler context and register value as we may use them
            # based on the user's context, or the action they select
            #

            dctx = self.controller.pctx.dctx
            reg_value = self.model.registers[reg_name]

            #
            # dynamically populate the right click context menu
            #

            menu.addAction(self._action_copy_value)
            menu.addAction(self._action_follow_in_dump)

            #
            # if the register conatins a value that falls within the database,
            # we want to show it and ensure it's active
            #

            menu.addAction(self._action_follow_in_disassembly)
            if dctx.is_mapped(reg_value):
                self._action_follow_in_disassembly.setEnabled(True)
            else:
                self._action_follow_in_disassembly.setEnabled(False)

        #
        # show the right click menu and wait for the user to selection an
        # action from the list of visible/active actions
        #

        action = menu.exec_(self.mapToGlobal(position))

        #
        # handle the user selected action
        #

        if action == self._action_copy_value:
            copy_to_clipboard("0x%08X" % reg_value)
        elif action == self._action_follow_in_disassembly:
            dctx.navigate(reg_value)
        elif action == self._action_follow_in_dump:
            self.controller.follow_in_dump(reg_name)

    def refresh(self):
        self.viewport().update()

    def _pos_to_field(self, pos):
        """
        Get the register field at the given cursor position.
        """
        for reg_name, field in self._reg_fields.items():
            full_field = QtCore.QRect(
                field.name_rect.topLeft(), field.next_rect.bottomRight()
            )
            if full_field.contains(pos):
                return field
        return None

    def _pos_to_reg(self, pos):
        """
        Get the register name at the given cursor position.
        """
        reg_field = self._pos_to_field(pos)
        return reg_field.name if reg_field else None

    def full_size(self):
        if not self.model.registers:
            return QtCore.QSize(0, 0)

        width = self._reg_pos[0] + self._default_width
        height = len(self.model.registers) * self._char_height

        return QtCore.QSize(width, height)

    def paintEvent(self, event):
        """
        Qt overload of widget painting.
        """

        if not self.model.registers:
            return

        painter = QtGui.QPainter(self.viewport())

        area_size = self.viewport().size()
        area_rect = self.viewport().rect()
        widget_size = self.full_size()

        painter.fillRect(area_rect, self.pctx.palette.reg_bg)

        brush_defualt = painter.brush()
        brush_selected = QtGui.QBrush(self.pctx.palette.standard_selection_bg)

        for reg_name in self.model.arch.REGISTERS:
            reg_value = self.model.registers[reg_name]
            reg_field = self._reg_fields[reg_name]

            # coloring for when the register is selected by the user
            if reg_name == self.model.focused_reg_name:
                painter.setBackground(brush_selected)
                painter.setBackgroundMode(QtCore.Qt.OpaqueMode)
                painter.setPen(self.pctx.palette.standard_selection_fg)

            # default / unselected register colors
            else:
                painter.setBackground(brush_defualt)
                painter.setBackgroundMode(QtCore.Qt.OpaqueMode)
                painter.setPen(self.pctx.palette.reg_name_fg)

            # draw register name
            painter.drawText(reg_field.name_rect, QtCore.Qt.AlignCenter, reg_name)

            reg_nibbles = self.model.arch.POINTER_SIZE * 2
            if reg_value is None:
                rendered_value = "?" * reg_nibbles
            else:
                rendered_value = f"%0{reg_nibbles}X" % reg_value

            # color register if its value changed as a result of T-1 (previous instr)
            if reg_name in self.model.delta_trace:
                painter.setPen(self.pctx.palette.reg_changed_trace_fg)

            # color register if its value changed as a result of navigation
            # TODO: disabled for now, because it seemed more confusing than helpful...
            elif reg_name in self.model.delta_navigation and False:
                painter.setPen(self.pctx.palette.reg_changed_navigation_fg)

            # no special highlighting, default register value color text
            else:
                painter.setPen(self.pctx.palette.reg_value_fg)

            # coloring for when the register is selected by the user
            if reg_name == self.model.focused_reg_value:
                painter.setPen(self.pctx.palette.standard_selection_fg)
                painter.setBackground(brush_selected)
                painter.setBackgroundMode(QtCore.Qt.OpaqueMode)

            # default / unselected register colors
            else:
                painter.setBackground(brush_defualt)
                painter.setBackgroundMode(QtCore.Qt.OpaqueMode)

            # draw register value
            painter.drawText(
                reg_field.value_rect, QtCore.Qt.AlignCenter, rendered_value
            )

            # draw register arrows
            for i, rect in enumerate([reg_field.prev_rect, reg_field.next_rect]):
                self._draw_arrow(painter, rect, i)

    def _draw_arrow(self, painter, rect, index):
        path = QtGui.QPainterPath()

        size = rect.height()
        assert size % 2, "Cursor triangle size must be odd"

        # the top point of the triangle
        top_x = rect.x() + (0 if index else rect.width())
        top_y = rect.y() + 1

        # bottom point of the triangle
        bottom_x = top_x
        bottom_y = top_y + size - 1

        # the 'tip' of the triangle pointing into towards the center of the trace
        tip_x = top_x + ((size // 2) * (1 if index else -1))
        tip_y = top_y + (size // 2)

        # start drawing from the 'top' of the triangle
        path.moveTo(top_x, top_y)

        # generate the triangle path / shape
        path.lineTo(bottom_x, bottom_y)
        path.lineTo(tip_x, tip_y)
        path.lineTo(top_x, top_y)

        # dev / debug helper
        # painter.setPen(QtCore.Qt.green)
        # painter.setBrush(QtGui.QBrush(QtGui.QColor("white")))
        # painter.drawRect(rect)

        # paint the defined triangle
        # TODO: don't hardcode colors
        painter.setPen(QtCore.Qt.black)

        if self._hovered_arrow == rect:
            if index:
                painter.setBrush(self.pctx.palette.arrow_next)
            else:
                painter.setBrush(self.pctx.palette.arrow_prev)
        else:
            painter.setBrush(self.pctx.palette.arrow_idle)

        painter.drawPath(path)


class RegisterField(object):
    def __init__(self, name, name_rect, value_rect, arrow_rects):
        self.name = name
        self.name_rect = name_rect
        self.value_rect = value_rect
        self.prev_rect = arrow_rects[0]
        self.next_rect = arrow_rects[1]
