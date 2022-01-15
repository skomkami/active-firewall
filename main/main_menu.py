from blocked_hosts.blocked_hosts_menu import BlockedHostsMenu
from config.config import DBConnectionConf
from menu.abstract_menu import AbstractMenu
from traffic.traffic_menu import TrafficMenu
import curses


class MainMenu(AbstractMenu):
    """
    Main menu. All available view can be selected from it.
    """

    def menu_options(self):
        return ['Show suspicious traffic', 'Blocked hosts list', 'Exit']

    def __init__(self, stdscr, db_config: DBConnectionConf):
        super().__init__(stdscr)
        self.stdscr = stdscr
        self.db_config = db_config

    def handle_action(self, selected_row, selected_page):
        row = selected_row % len(self.menu_options())
        if row == 0:
            return TrafficMenu(self.stdscr, self.db_config)
        elif row == 1:
            return BlockedHostsMenu(self.stdscr, self.db_config)
        else:
            return None
    
    def has_next_option(self, selected_row):
        return selected_row < len(self.menu_options())

    def show_content(self, selected_row, selected_page, width, height):
        selected_row_index = selected_row % len(self.menu_options())

        for idx, item in enumerate(self.menu_options()):
            x = width // 2 - len(item) // 2
            y = height // 2 - len(self.menu_options()) // 2 + idx
            if idx == selected_row_index:
                self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(y, x, item)
            if idx == selected_row_index:
                self.stdscr.attroff(curses.color_pair(2))

    def title(self):
        return "Main menu"
