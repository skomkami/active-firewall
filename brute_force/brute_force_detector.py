from time import sleep
from typing import List

from config.config import DBConnectionConf, BruteForceModuleConf, AnomalyDetectorConf
from brute_force.detectors.login_detector import LoginDetector
from database.bruteforce_repo import BruteForceRepo
from database.detections_repo import DetectionRepo
from database.blocked_hosts_repo import BlockedHostRepo
from anomaly_detection.detect import AnomalyDetector
from brute_force.detectors.ssh_login_detector import SSHLoginDetector
from brute_force.detectors.apache2_login_detector import Apache2LoginDetector
from brute_force.detectors.imap_pop3_login_detector import ImapPop3LoginDetector


class BruteForceDetector:
    """
    Main facade for BruteFroce module. Holds all paramaters and instances required for running brute force attack
    detectors. Currently it creates certain detectors for each service base on config provided.

    Main method is 'run'. It runs in infinite loop, in which it runs 'run' method for each of detectors.
    """
    def __init__(self, db_config: DBConnectionConf, config: BruteForceModuleConf, anomaly_config: AnomalyDetectorConf):
        self.db_config = db_config
        self.detections_repo = DetectionRepo(self.db_config)
        self.stats_repo = None
        self.blocked_hosts_repo = None
        self.anomaly_detector = AnomalyDetector(anomaly_config)
        self.config = config
        self.periodicity = self.config.periodicity
        self.delay = 1/self.config.frequency
        self.detectors = self.__get_detectors()

    def run(self):
        self.__init_repos()
        while True:
            for detector in self.detectors:
                detector.run(self.detections_repo, self.stats_repo, self.blocked_hosts_repo)
            sleep(self.delay)

    def __init_repos(self):
        self.detections_repo = DetectionRepo(self.db_config)
        self.stats_repo = BruteForceRepo(self.db_config)
        self.blocked_hosts_repo = BlockedHostRepo(self.db_config)

    def __get_detectors(self) -> List[LoginDetector]:
        detectors = list()
        services = self.config.services.available_services
        for service_name in services:
            detector = self.__get_single_detector(service_name)
            if not detector:
                continue
            detectors.append(detector)

        return detectors

    def __get_single_detector(self, name: str) -> LoginDetector:
        name = name.lower()
        default_args = self.__get_detector_default_args()
        if name == 'ssh':
            detector = SSHLoginDetector(self.config.services.ssh, **default_args)
        elif name == 'apache2':
            detector = Apache2LoginDetector(self.config.services.apache2, **default_args)
        elif name == 'imappop3':
            detector = ImapPop3LoginDetector(self.config.services.imappop3, **default_args)
        else:
            detector = None

        return detector

    def __get_detector_default_args(self):
        return {
            'detections_repo': self.detections_repo,
            'anomaly_detector': self.anomaly_detector,
            'periodicity': self.periodicity
        }


