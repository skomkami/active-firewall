from datetime import datetime
from re import findall

from brute_force.detectors.login_detector import LoginDetector
from database.detections_repo import DetectionRepo
from model.detection import ModuleName
from config.config import ServiceConfig


class ImapPop3LoginDetector(LoginDetector):

    def __init__(self, config: ServiceConfig, repo: DetectionRepo):
        super().__init__(ModuleName.IMAP_POP3_LOGIN_DETECTOR, config, repo, '%b %d %H:%M:%S')
        self.log_file_path = '/var/log/mail.log'
        self.get_logs_command = "awk '/^{from_date}.*/,/$1>=start/' {file_path} | grep -a 'Authentication failure'"

    @staticmethod
    def get_log_timestamp(log: str) -> datetime:
        raw_timestamp = ' '.join(log.split()[0:3])
        year = datetime.now().year

        return datetime.strptime(f'{year} {raw_timestamp}', '%Y %b %d %H:%M:%S')

    def get_previous_log_timestamp(self, log: str) -> str:
        return self.get_log_timestamp(log).strftime(self.timestamp_format)

    @staticmethod
    def get_ip(log: str) -> str:
        [ip] = findall(r'[0-9]+(?:\.[0-9]+){3}', log)

        return ip

    @staticmethod
    def get_port(log: str) -> str:
        return '80'
