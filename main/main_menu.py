from config.config import DBConnectionConf
from menu.abstract_menu import AbstractMenu
from traffic.traffic_menu import TraficMenu
import curses


class MainMenu(AbstractMenu):

    def menuOptions(self):
        return ['Show suspicious traffic', 'Exit']

    def __init__(self, stdscr, dbConfig: DBConnectionConf):
        super().__init__(stdscr)
        self.stdscr = stdscr
        self.dbConfig = dbConfig

    def handleAction(self, selectedRow, selected_page):
        if selectedRow == 0:
            return TraficMenu(self.stdscr, self.dbConfig)
        else:
            return None

    def show_content(self, selected_row, selected_page, width, height):
        selected_row_index = selected_row % len(self.menuOptions())

        for idx, item in enumerate(self.menuOptions()):
            x = width // 2 - len(item) // 2
            y = height // 2 - len(self.menuOptions()) // 2 + idx
            if idx == selected_row_index:
                self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(y, x, item)
            if idx == selected_row_index:
                self.stdscr.attroff(curses.color_pair(2))

    def title(self):
        return "Main menu"
