from datetime import datetime
from re import findall

from brute_force.detectors.login_detector import LoginDetector
from database.detections_repo import DetectionRepo
from database.bruteforce_repo import BruteForceRepo
from model.detection import ModuleName
from config.config import ServiceConfig, Periodicity


class Apache2LoginDetector(LoginDetector):

    def __init__(
            self,
            config: ServiceConfig,
            repo: DetectionRepo,
            stats_repo: BruteForceRepo,
            periodicity: Periodicity
    ):
        super().__init__(ModuleName.APACHE2_LOGIN_DETECTOR, config, repo, stats_repo, r'%d\/%b\/%Y:%H:%M:%S',
                         periodicity)
        self.log_file_path = '/var/log/apache2/access.log'
        self.get_logs_command = "awk '/^.*{from_date}.*/,/$1>=start/' {file_path} | grep -a 401"

    @staticmethod
    def get_log_timestamp(log: str) -> datetime:
        raw_timestamp = findall(r'\d+/\w+/\d+:\d+:\d+:\d+', log)[0]

        return datetime.strptime(raw_timestamp, '%d/%b/%Y:%H:%M:%S')

    def get_previous_log_timestamp(self, log: str) -> str:
        return self.get_log_timestamp(log).strftime(self.timestamp_format)

    @staticmethod
    def get_ip(log: str) -> str:
        try:
            [ip] = findall(r'[0-9]+(?:\.[0-9]+){3}', log[:15])
        except ValueError:
            # There is no client IP in log - most likely server IP was captured.
            ip = None

        return ip

    @staticmethod
    def get_port(log: str) -> str:
        return '80'
