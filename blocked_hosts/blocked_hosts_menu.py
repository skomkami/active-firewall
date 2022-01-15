import curses

from config.config import DBConnectionConf
from database.blocked_hosts_repo import BlockedHostRepo
from ip_access_manager.manager import IPAccessManager
from menu.abstract_menu import AbstractMenu
from model.blocked_host import BlockState, BlockedHost
from utils.log import log_to_file


class BlockedHostsMenu(AbstractMenu):
    """
    This menu displays list of blocked hosts and allows to unblock them by pressing `u` key when given device is
    selected in menu.
    """

    def __init__(self, stdscr, db_config: DBConnectionConf):
        super().__init__(stdscr)
        self.stdscr = stdscr
        self.db_config = db_config
        self.blocked_hosts_repo = BlockedHostRepo(self.db_config)
        self.current_page = 1
        self.ip_manager = IPAccessManager()
        self.selected_block: BlockedHost = None

    def menu_options(self):
        return ["Exit"]

    def handle_action(self, selected_row, selected_page):
        return None

    def handle_custom_action(self, key, selected_row, selected_page):
        if key == ord('u') and self.selected_block is not None and self.selected_block.state is BlockState.BLOCKED:
            current_ip = self.selected_block.ip_address
            log_to_file('selected_row with ip: ' + current_ip)
            self.blocked_hosts_repo.update_field_for_ip(current_ip, "state", "'{}'".format(BlockState.UNBLOCKED.name))
            self.ip_manager.allow_access_from_ip(current_ip)

    def has_next_page(self):
        return len(self.blocked_hosts_repo.get_all(offset=10 * self.current_page)) >= 10

    def has_next_option(self, selected_row):
        return True

    def show_content(self, selected_row, selected_page, width, height):
        self.current_page = selected_page
        blocked_hosts = self.blocked_hosts_repo.get_all(offset=10 * selected_page)
        if len(blocked_hosts) > 0:
            selected_row_index = selected_row % len(blocked_hosts)
            self.selected_block = blocked_hosts[selected_row_index]
            row_display_width = 80

            x = width // 2 - row_display_width // 2

            header_y_pos = height // 2 - len(blocked_hosts) // 2 - 1
            nav_y_pos = height // 2 + len(blocked_hosts) // 2 + 1

            self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(header_y_pos, x, "IP ADDRESS")
            self.stdscr.addstr(header_y_pos, x + 17, "STATE")
            self.stdscr.addstr(header_y_pos, x + 40, "STATE SINCE")
            # self.stdscr.addstr(header_y_pos, x + 60, "MODULE")
            self.stdscr.attroff(curses.color_pair(2))

            for idx, blocked_host in enumerate(blocked_hosts):
                y = height // 2 - len(blocked_hosts) // 2 + idx
                if idx == selected_row_index:
                    self.stdscr.attron(curses.color_pair(2))

                self.stdscr.addstr(y, x, blocked_host.ip_address)
                self.stdscr.addstr(y, x + 17, blocked_host.state.name)
                self.stdscr.addstr(y, x + 40, str(blocked_host.state_since))
                # self.stdscr.addstr(y, x + 60, detection.module_name.name)
                if idx == selected_row_index:
                    self.stdscr.attroff(curses.color_pair(2))

            prev_page = "<- Previous page"
            next_page = "Next page ->"
            self.stdscr.attron(curses.color_pair(2))
            if selected_page > 0:
                self.stdscr.addstr(nav_y_pos, x, prev_page)
            if len(blocked_hosts) >= 10:
                self.stdscr.addstr(nav_y_pos, x + row_display_width - len(next_page) - 1, next_page)
            self.stdscr.attroff(curses.color_pair(2))
            if self.selected_block.state is BlockState.BLOCKED:
                self.custom_menu_options()
        else:
            no_blocked_str = "No blocked hosts yet"
            self.stdscr.addstr(height // 2, (width - len(no_blocked_str)) // 2, no_blocked_str)

    def custom_menu_options(self):
        h, w = self.stdscr.getmaxyx()
        unblock_host_string = "UNBLOCK HOST- [U]"

        self.stdscr.addstr(1, w - len(unblock_host_string), unblock_host_string)

    def title(self):
        return "Blocked hosts menu"
