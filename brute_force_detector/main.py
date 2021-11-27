from ssh_login_detector.log_parsers import LogParser
from config.config import BruteForceModuleConf


def main() -> None:
    detector = LogParser()
    detector.run()
    print('Done!')


if __name__ == '__main__':
    main()
