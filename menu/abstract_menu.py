from abc import ABC, abstractmethod


class AbstractMenu(ABC):

    @abstractmethod
    def menuOptions(self):
        return []

    @abstractmethod
    def title(self):
        return "Abstract Menu"

    # it should return entered submenu or None (then app should return to parent menu)
    @abstractmethod
    def handleAction(self, selected_row, selected_page):
        return None

    def __init__(self, stdscr):
        self.stdscr = stdscr

    @abstractmethod
    def show_content(self, selected_row, selected_page, width, height):
        return None
    
    def has_next_page(self):
        return False

    def show(self, selected_row, selected_page = 0):
        self.stdscr.clear()
        h, w = self.stdscr.getmaxyx()
        esc_string = "QUIT - [Q]"
        # self.stdscr.attron(curses.color_pair(1))

        self.stdscr.addstr(0, 0, self.title())
        self.stdscr.addstr(0, w-len(esc_string), esc_string)

        self.show_content(selected_row, selected_page, w, h)

        # self.stdscr.attroff(curses.color_pair(1))
        self.stdscr.refresh()
