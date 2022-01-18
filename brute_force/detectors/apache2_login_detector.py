from datetime import datetime
from re import findall

from brute_force.detectors.login_detector import LoginDetector
from anomaly_detection.detect import AnomalyDetector
from database.detections_repo import DetectionRepo
from model.detection import ModuleName
from config.config import ServiceConfig, Periodicity


class Apache2LoginDetector(LoginDetector):
    """
    Login detector preapred in order to detect login attempts to Apache2 HTTP server.
    """
    def __init__(
            self,
            config: ServiceConfig,
            detections_repo: DetectionRepo,
            anomaly_detector: AnomalyDetector,
            periodicity: Periodicity
    ):
        super().__init__(ModuleName.APACHE2_LOGIN_DETECTOR, config, detections_repo, anomaly_detector, r'%d\/%b\/%Y:%H:%M:%S',
                         periodicity)
        self.log_file_path = '/var/log/apache2/access.log'
        self.get_logs_command = "awk '/^.*{from_date}.*/,/$1>=start/' {file_path} | grep -a 401"

    @staticmethod
    def get_log_timestamp(log: str) -> datetime:
        raw_timestamp = findall(r'\d+/\w+/\d+:\d+:\d+:\d+', log)[0]

        return datetime.strptime(raw_timestamp, '%d/%b/%Y:%H:%M:%S')

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
