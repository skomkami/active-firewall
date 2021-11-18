import curses

from main.main_menu import MainMenu
from config.config import AppConfig, readConf
from arguments.read_args import getArgs


def main(stdscr):
  config = readConf(getArgs()['config_file'] or 'config.json')
  curses.curs_set(0)
  curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
  curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)

  currentRow = 0

  menusPath = []
  # stdscr.addstr(1, 1, str(config.dosModuleConf.maxPackets))
  # import time
  # stdscr.refresh()
  # time.sleep(1)

  currentMenu = MainMenu(stdscr)
  currentMenu.show(currentRow)

  while 1:
    key = stdscr.getch()
    if key == curses.KEY_UP:
      currentRow+=1
    elif key == curses.KEY_DOWN:
      currentRow-=1
    elif key == curses.KEY_ENTER or key in [10, 13]:
      newMenu = currentMenu.handleAction(currentRow)
      if newMenu == None and len(menusPath) > 0:
        currentMenu = menusPath.pop()
      elif newMenu == None:
        break
      else:
        menusPath.append(currentMenu)
        currentMenu = newMenu        
      
    currentMenu.show(currentRow)

curses.wrapper(main)