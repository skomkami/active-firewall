import curses
from multiprocessing import Process
from typing import List

from arguments.read_args import getArgs
from config.config import AppConfig, readConf
from main.main_menu import MainMenu
from scanning.port_scanning_detector import portScanningDetection
from brute_force_detector.ssh_login_detector.detector import SSHLoginDetector


def runProcesses(config: AppConfig) -> List[Process]:
    portScanningDetectionProc = None
    dosModuleProc = None
    bruteForceProc = None
    if config.portScannerConf.enabled:
        portScanningDetectionProc = Process(target=portScanningDetection, args=())
        portScanningDetectionProc.start()
    if config.bfModuleConf.enabled:
        bf_config = config.bfModuleConf
        frequency = bf_config.frequency
        attempt_limit = bf_config.attemptLimit
        detector = SSHLoginDetector(frequency, attempt_limit)
        bruteForceProc = Process(target=detector.run, args=())
        bruteForceProc.start()

    return [portScanningDetectionProc, dosModuleProc, bruteForceProc]


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
    processes = runProcesses(config)

    currentMenu = MainMenu(stdscr)
    currentMenu.show(currentRow)

    while 1:
        key = stdscr.getch()
        if key == curses.KEY_UP:
            currentRow += 1
        elif key == curses.KEY_DOWN:
            currentRow -= 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            newMenu = currentMenu.handleAction(currentRow)
            if newMenu == None and len(menusPath) > 0:
                currentMenu = menusPath.pop()
            elif newMenu == None:
                for process in processes:
                    if process != None:
                        process.terminate()
                break
            else:
                menusPath.append(currentMenu)
                currentMenu = newMenu

        currentMenu.show(currentRow)


curses.wrapper(main)
