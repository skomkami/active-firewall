from ssh_login_detector.detectors import LogAnalyzer
from config.config import BruteForceModuleConf


def main() -> None:
    detector = LogAnalyzer()
    detector.run()
    print('Done!')


if __name__ == '__main__':
    main()
