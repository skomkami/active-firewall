from brute_force.detectors.apache2_login_detector import Apache2LoginDetector
from brute_force.detectors.ssh_login_detector import SSHLoginDetector
from brute_force.brute_force_detector import BruteForceDetector
from config.config import DBConnectionConf, BruteForceModuleConf
from config.config import AppConfig, readConf


def main() -> None:
    # detector = SSHLoginDetector(DBConnectionConf)
    # detector = Apache2LoginDetector(DBConnectionConf)
    config = AppConfig()
    detector = BruteForceDetector(config.dbConnectionConf, config.bfModuleConf)
    detector.run()
    print('Done!')


if __name__ == '__main__':
    main()
