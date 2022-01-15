from datetime import datetime
from re import findall

from brute_force.detectors.login_detector import LoginDetector
from database.detections_repo import DetectionRepo
from database.bruteforce_repo import BruteForceRepo
from model.detection import ModuleName
from config.config import ServiceConfig, Periodicity


class ImapPop3LoginDetector(LoginDetector):
    """
    Login detector preapred in order to detect login attempts to IMAP/POP3 server.
    """
    def __init__(
            self,
            config: ServiceConfig,
            repo: DetectionRepo,
            stats_repo: BruteForceRepo,
            periodicity: Periodicity
    ):
        super().__init__(ModuleName.IMAP_POP3_LOGIN_DETECTOR, config, repo, stats_repo, '%b %d %H:%M:%S', periodicity)
        self.log_file_path = '/var/log/mail.log'
        self.get_logs_command = "awk '/^{from_date}.*/,/$1>=start/' {file_path} | grep -a 'Authentication failure'"

    @staticmethod
    def get_log_timestamp(log: str) -> datetime:
        raw_timestamp = ' '.join(log.split()[0:3])
        year = datetime.now().year

        return datetime.strptime(f'{year} {raw_timestamp}', '%Y %b %d %H:%M:%S')

    @staticmethod
    def get_ip(log: str) -> str:
        [ip] = findall(r'[0-9]+(?:\.[0-9]+){3}', log)

        return ip

    @staticmethod
    def get_port(log: str) -> str:
        return '80'
