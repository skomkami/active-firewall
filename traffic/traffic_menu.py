from config.config import DBConnectionConf
from database.detections_repo import DetectionRepo
from menu.abstract_menu import AbstractMenu
import curses


class TrafficMenu(AbstractMenu):
    """
    Menu where all detected suspicious traffic can be listed. Compared to BlockedHostsMenu, it can show history
    for hosts.
    """

    def __init__(self, stdscr, db_config: DBConnectionConf):
        super().__init__(stdscr)
        self.stdscr = stdscr
        self.db_config = db_config
        self.detections_repo = DetectionRepo(self.db_config)
        self.current_page = 1

    def menu_options(self):
        return ["Exit"]

    def handle_action(self, selected_row, selected_page):
        return None

    def has_next_page(self):
        return len(self.detections_repo.get_all(offset=10*self.current_page)) >= 10

    def show_content(self, selected_row, selected_page, width, height):
        self.current_page = selected_page
        detections = self.detections_repo.get_all(offset=10*selected_page)

        if len(detections) > 0:
            # selected_row_index = selected_row % len(self.menuOptions())
            row_display_width = 80

            x = width // 2 - row_display_width // 2
            address_pos = x + 12
            timestamp_pos = x + 33
            module_name_pos = x + 68

            header_y_pos = height // 2 - len(detections) // 2 - 1
            nav_y_pos = height // 2 + len(detections) // 2 + 1

            self.stdscr.attron(curses.color_pair(2))
            self.stdscr.addstr(header_y_pos, x, "ID")
            self.stdscr.addstr(header_y_pos, address_pos, "ATTACKER ADDRESS")
            self.stdscr.addstr(header_y_pos, timestamp_pos, "DETECTED AT")
            self.stdscr.addstr(header_y_pos, module_name_pos, "MODULE")
            self.stdscr.attroff(curses.color_pair(2))

            for idx, detection in enumerate(detections):
                y = height // 2 - len(detections) // 2 + idx

                self.stdscr.addstr(y, x, str(detection.id))
                self.stdscr.addstr(y, address_pos, detection.attacker_ip_address)
                self.stdscr.addstr(y, timestamp_pos, str(detection.detection_time))
                self.stdscr.addstr(y, module_name_pos, detection.module_name.name)

            prev_page = "<- Previous page"
            next_page = "Next page ->"
            self.stdscr.attron(curses.color_pair(2))
            if selected_page > 0:
                self.stdscr.addstr(nav_y_pos, x, prev_page)
            if len(detections) >= 10:
                self.stdscr.addstr(nav_y_pos, x + row_display_width - len(next_page) - 1, next_page)
            self.stdscr.attroff(curses.color_pair(2))
        else:
            no_detections_str = "No detections yet"
            self.stdscr.addstr(height//2, (width -len(no_detections_str))//2, no_detections_str)

    def title(self):
        return "Traffic menu"
