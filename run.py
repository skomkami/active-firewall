import curses
from multiprocessing import Process
from typing import List

from arguments.read_args import getArgs
from config.config import AppConfig, readConf
from dos.dos_scan_detector import DosAttackDetector
from main.main_menu import MainMenu
from scanning.port_scanning_detector import PortScanningDetector
from brute_force.brute_force_detector import BruteForceDetector
from utils.log import log_to_file


def runProcesses(config: AppConfig) -> List[Process]:
    portScanningDetectionProc = None
    dosModuleProc = None
    bruteForceProc = None
    if config.portScannerConf.enabled:
        psConfig = config.portScannerConf
        detector = PortScanningDetector(config.dbConnectionConf, psConfig)
        portScanningDetectionProc = Process(target=detector.run, args=())
        portScanningDetectionProc.start()
    if config.bfModuleConf.enabled:
        detector = BruteForceDetector(config.dbConnectionConf, config.bfModuleConf)
        bruteForceProc = Process(target=detector.run, args=())
        bruteForceProc.start()
    if config.dosModuleConf.enabled:
        detector = DosAttackDetector(config.dbConnectionConf, config.dosModuleConf)
        dosModuleProc = Process(target=detector.run, args=())
        dosModuleProc.start()

    return [portScanningDetectionProc, dosModuleProc, bruteForceProc]


def terminate_processes(processes: list) -> list:
    for process in processes:
        if process != None:
            process.terminate()

    return processes


def main(stdscr):
    config = readConf(getArgs()['config_file'] or 'config.json')
    curses.curs_set(0)
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)

    current_row = 0
    current_page = 0

    menus_path = []
    processes = runProcesses(config)

    current_menu = MainMenu(stdscr, config.dbConnectionConf)
    current_menu.show(current_row)

    while 1:
        try:
            key = stdscr.getch()
            if key == curses.KEY_UP:
                current_row -= 1
            elif key == curses.KEY_DOWN:
                current_row += 1
            elif key == curses.KEY_LEFT:
                if current_page > 0:
                    current_page -= 1
            elif key == curses.KEY_RIGHT and current_menu.has_next_page():
                current_page += 1
            elif key == ord('q'):
                if len(menus_path) > 0:
                    current_menu = menus_path.pop()
                else:
                    terminate_processes(processes)
                    break
            elif key == curses.KEY_ENTER or key in [10, 13]:
                newMenu = current_menu.handle_action(current_row, current_page)
                if newMenu == current_menu:
                    pass
                elif newMenu is None and len(menus_path) > 0:
                    current_menu = menus_path.pop()
                elif newMenu is None:
                    terminate_processes(processes)
                    break
                else:
                    menus_path.append(current_menu)
                    current_menu = newMenu
            else:
                log_to_file("wtf: " + str(current_row))
                current_menu.handle_custom_action(key, current_row, current_page)

            current_menu.show(current_row, current_page)
        except Exception as msg:
            log_to_file("error in menu: " + str(msg))


curses.wrapper(main)
