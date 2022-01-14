import curses
from multiprocessing import Process
from typing import List

from arguments.read_args import getArgs
from config.config import AppConfig, readConf
from dos.dos_scan_detector import DosAttackDetector
from main.main_menu import MainMenu
from scanning.port_scanning_detector import PortScanningDetector
from brute_force_detector.detectors.ssh_login_detector import SSHLoginDetector


def runProcesses(config: AppConfig) -> List[Process]:
    portScanningDetectionProc = None
    dosModuleProc = None
    bruteForceProc = None
    if config.portScannerConf.enabled:
        psConfig = config.portScannerConf
        lanIp = psConfig.lanIp
        detector = PortScanningDetector(config.dbConnectionConf, psConfig, lanIp)
        portScanningDetectionProc = Process(target=detector.run, args=())
        portScanningDetectionProc.start()
    if config.bfModuleConf.enabled:
        bf_config = config.bfModuleConf
        frequency = bf_config.frequency
        attempt_limit = bf_config.attemptLimit
        detector = SSHLoginDetector(config.dbConnectionConf, frequency, attempt_limit)
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
        key = stdscr.getch()
        if key == curses.KEY_UP:
            current_row -= 1
        elif key == curses.KEY_DOWN:
            current_row += 1
        elif key == curses.KEY_LEFT:
            if current_page > 0:
                current_page-=1
        elif key == curses.KEY_RIGHT and current_menu.has_next_page():
            current_page+=1
        elif key == ord('q'):
            if len(menus_path) > 0:
                current_menu = menus_path.pop()
            else:
                terminate_processes(processes)
                break
        elif key == curses.KEY_ENTER or key in [10, 13]:
            newMenu = current_menu.handleAction(current_row, current_page)
            if newMenu == current_menu:
                pass
            elif newMenu == None and len(menus_path) > 0:
                current_menu = menus_path.pop()
            elif newMenu == None:
                terminate_processes(processes)
                break
            else:
                menus_path.append(current_menu)
                current_menu = newMenu

        current_menu.show(current_row, current_page)


curses.wrapper(main)
