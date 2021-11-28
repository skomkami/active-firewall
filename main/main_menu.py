from menu.abstract_menu import AbstractMenu
from traffic.traffic_menu import TraficMenu


class MainMenu(AbstractMenu):

    def menuOptions(self):
        return ['Show suspicious traffic', 'Exit']

    def __init__(self, stdscr):
        super().__init__(stdscr)
        self.stdscr = stdscr

    def handleAction(self, selectedRow):
        if selectedRow % len(self.menuOptions()) == 0:
            return TraficMenu(self.stdscr)
        else:
            return None

    def title(self):
        return "Main menu"
