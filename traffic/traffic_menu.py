from config.config import DBConnectionConf
from database.detections_repo import DetectionRepo
from menu.abstract_menu import AbstractMenu
import curses


class TraficMenu(AbstractMenu):
    def __init__(self, stdscr, db_config: DBConnectionConf):
        super().__init__(stdscr)
        self.stdscr = stdscr
        self.dbConfig = db_config
        self.detections_repo = DetectionRepo(self.dbConfig)
        self.current_page = 1

    def menuOptions(self):
        return ["Exit"]

    def handleAction(self, selected_row, selected_page):
        return None

    def has_next_page(self):
        return len(self.detections_repo.get_all(offset=10*self.current_page)) >= 10

    def show_content(self, selected_row, selected_page, width, height):
        self.current_page = selected_page
        detections = self.detections_repo.get_all(offset=10*selected_page)
        # selected_row_index = selected_row % len(self.menuOptions())
        row_display_width = 80

        x = width // 2 - row_display_width // 2

        header_y_pos = height // 2 - len(detections) // 2 - 1
        nav_y_pos = height // 2 + len(detections) // 2 + 1

        self.stdscr.attron(curses.color_pair(2))
        self.stdscr.addstr(header_y_pos, x, "ID")
        self.stdscr.addstr(header_y_pos, x+4, "ATTACKER ADDRESS")
        self.stdscr.addstr(header_y_pos, x+25, "DETECTED AT")
        self.stdscr.addstr(header_y_pos, x+60, "MODULE")
        self.stdscr.attroff(curses.color_pair(2))

        for idx, detection in enumerate(detections):
            y = height // 2 - len(detections) // 2 + idx
            
            self.stdscr.addstr(y, x, str(detection.detection_id))
            self.stdscr.addstr(y, x+4, detection.attacker_ip_address)
            self.stdscr.addstr(y, x+25, str(detection.detection_time))
            self.stdscr.addstr(y, x+60, detection.module_name.name)

        prev_page = "<- Previous page"
        next_page = "Next page ->"
        self.stdscr.attron(curses.color_pair(2))
        if selected_page > 0:
            self.stdscr.addstr(nav_y_pos, x, prev_page)
        if len(detections) >= 10:
            self.stdscr.addstr(nav_y_pos, x + row_display_width - len(next_page) - 1, next_page)
        self.stdscr.attroff(curses.color_pair(2))

    def title(self):
        return "Traffic menu"
