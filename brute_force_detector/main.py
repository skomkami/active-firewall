from ssh_login_detector.detector import SSHLoginDetector
from config.config import BruteForceModuleConf
from config.config import DBConnectionConf


def main() -> None:
    detector = SSHLoginDetector(DBConnectionConf)
    detector.run()
    print('Done!')


if __name__ == '__main__':
    main()
