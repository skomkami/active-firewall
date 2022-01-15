from time import sleep
from typing import List

from config.config import DBConnectionConf, BruteForceModuleConf
from brute_force.detectors.login_detector import LoginDetector
from database.bruteforce_repo import BruteForceRepo
from database.detections_repo import DetectionRepo
from config.config import ServiceConfig
from brute_force.detectors.ssh_login_detector import SSHLoginDetector
from brute_force.detectors.apache2_login_detector import Apache2LoginDetector
from brute_force.detectors.imap_pop3_login_detector import ImapPop3LoginDetector


class BruteForceDetector:

    def __init__(self, db_config: DBConnectionConf, config: BruteForceModuleConf):
        self.db_config = db_config
        self.repo = DetectionRepo(self.db_config)
        self.stats_repo = None
        self.config = config
        self.periodicity = self.config.periodicity
        self.delay = 1/self.config.frequency
        self.detectors = self.__get_detectors()

    def init_repo(self):
        self.stats_repo = BruteForceRepo(self.db_config)

    def run(self):
        self.repo = DetectionRepo(self.db_config)
        while True:
            for detector in self.detectors:
                detector.run(self.repo)
            sleep(self.delay)

    def __get_detectors(self) -> List[LoginDetector]:
        detectors = list()
        services = self.config.services
        for name, config in services:
            detector = self.__get_single_detector(name, config)
            if not detector:
                continue
            detectors.append(detector)
        return detectors

    def __get_single_detector(self, name: str, config: ServiceConfig) -> LoginDetector:
        name = name.lower()
        if name == 'ssh':
            detector = SSHLoginDetector(config, self.repo, self.stats_repo, self.periodicity)
        elif name == 'apache2':
            detector = Apache2LoginDetector(config, self.repo, self.stats_repo, self.periodicity)
        elif name == 'imappop3':
            detector = ImapPop3LoginDetector(config, self.repo, self.stats_repo, self.periodicity)
        else:
            detector = None

        return detector



