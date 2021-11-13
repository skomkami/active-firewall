from menu.abstract_menu import AbstractMenu

class TraficMenu(AbstractMenu):
  def __init__(self, stdscr):
    super().__init__(stdscr)
    self.stdscr = stdscr

  def menuOptions(self):
      return ["Exit"]

  def handleAction(self, selectedRow):
      return None

  def title(self):
      return "Trafic menu"