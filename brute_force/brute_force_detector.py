from time import sleep
from typing import List

from config.config import DBConnectionConf, BruteForceModuleConf
from brute_force.detectors.login_detector import LoginDetector
from brute_force.detectors.ssh_login_detector import SSHLoginDetector
from brute_force.detectors.apache2_login_detector import Apache2LoginDetector
from database.detections_repo import DetectionRepo
from config.config import ServiceConfig


def log(text: str):
    with open('brute_force/logs.txt', 'a') as f:
        print(text, file=f)


class BruteForceDetector:

    def __init__(self, db_config: DBConnectionConf, config: BruteForceModuleConf):
        self.db_config = db_config
        self.config = config
        self.delay = 1/self.config.frequency
        self.detectors = self.__get_detectors()

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

    @staticmethod
    def __get_single_detector(name: str, config: ServiceConfig) -> LoginDetector:
        name = name.lower()
        if name == 'ssh':
            detector = SSHLoginDetector(config)
        elif name == 'apache2':
            detector = Apache2LoginDetector(config)
        else:
            detector = None

        return detector



