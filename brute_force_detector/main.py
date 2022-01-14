from detectors.apache2_login_detector import Apache2LoginDetector
from config.config import BruteForceModuleConf
from config.config import DBConnectionConf


def main() -> None:
    detector = Apache2LoginDetector(DBConnectionConf)
    detector.run()
    print('Done!')


if __name__ == '__main__':
    main()
