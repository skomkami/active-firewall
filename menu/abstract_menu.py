from abc import ABC, abstractmethod


class AbstractMenu(ABC):

    @abstractmethod
    def menu_options(self):
        return []

    @abstractmethod
    def title(self):
        return "Abstract Menu"

    # it should return entered submenu or None (then app should return to parent menu)
    @abstractmethod
    def handle_action(self, selected_row, selected_page):
        return None

    def handle_custom_action(self, key, selected_row, selected_page):
        return

    def __init__(self, stdscr):
        self.stdscr = stdscr

    @abstractmethod
    def show_content(self, selected_row, selected_page, width, height):
        return None
    
    def has_next_page(self):
        return False

    def has_next_option(self, selected_row):
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
