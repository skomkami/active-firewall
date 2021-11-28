import curses
from abc import ABC, abstractclassmethod


class AbstractMenu(ABC):
    @abstractclassmethod
    def menuOptions(self):
        return []

    @abstractclassmethod
    def title(self):
        return "Abstract Menu"

    # it should return entered submenu or None (then app should return to parent menu)
    @abstractclassmethod
    def handleAction(self, selectedRow):
        return None

    def __init__(self, stdscr):
        self.stdscr = stdscr

    def show(self, selectedRow):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        # self.stdscr.attron(curses.color_pair(1))

        selectedRowIndex = selectedRow % len(self.menuOptions())
        self.stdscr.addstr(0, 0, self.title())

        for idx, item in enumerate(self.menuOptions()):
            x = w // 2 - len(item) // 2
            y = h // 2 - len(self.menuOptions()) // 2 + idx
            if idx == selectedRowIndex:
                self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(y, x, item)
            if idx == selectedRowIndex:
                self.stdscr.attroff(curses.color_pair(2))

        # self.stdscr.attroff(curses.color_pair(1))
        self.stdscr.refresh()
