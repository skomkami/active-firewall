from ssh_login_detector.detector import SSHLoginDetector
from config.config import BruteForceModuleConf


def main() -> None:
    detector = SSHLoginDetector()
    detector.run()
    print('Done!')


if __name__ == '__main__':
    main()
