from abc import ABC, abstractmethod
from re import findall
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from subprocess import Popen, PIPE
from platform import system
from os.path import exists

from database.detections_repo import DetectionRepo
from database.bruteforce_repo import BruteForceRepo
from brute_force.brute_force_stats import BruteForceRunningStats, BruteForceStats
from model.persistent_stats import BruteForcePersistentStats
from ip_access_manager.manager import IPAccessManager
from model.detection import Detection
from config.config import ServiceConfig, Periodicity
from model.detection import ModuleName


class ErrorMessages(Enum):
    INVALID_OS_MSG = 'Log parser is not able to be ran on {_os} system.'


@dataclass
class IPInfo:
    ip: str
    attempts_number: int = 0
    timestamps: list = field(default_factory=list)
    ports_attempted: set = field(default_factory=set)
    suspicious_address: bool = False

    def __repr__(self):
        return f'\nStats for IP address: {self.ip}\n' \
               f'Number of attempts: {self.attempts_number}\n' \
               f'Timestamps of attempts: {", ".join(timestamp.strftime("%H:%M:%S %d/%m/%Y") for timestamp in self.timestamps)}\n' \
               f'Ports attacked: {", ".join(self.ports_attempted)}\n' \
               f'Address is suspicious: {"yes" if self.suspicious_address else "no"}\n'


class LoginDetector(ABC):

    def __init__(
            self,
            name: ModuleName,
            config: ServiceConfig,
            repo: DetectionRepo,
            stats_repo: BruteForceRepo,
            timestamp_format: str,
            periodicity: Periodicity
    ):
        self.__check_os()
        self.name = name
        self.attempt_limit = config.attemptLimit
        self.enabled = config.enabled
        self.repo = repo
        self.stats_repo = stats_repo
        self.parsed_logs = dict()
        self.timestamp_format = timestamp_format
        self.stats = BruteForceRunningStats.init(datetime.now(), periodicity)
        self.previous_log_timestamp = self.get_most_recent_log_timestamp()
        self.get_logs_command = None
        self.log_file_path = None
        self.config_name = self.name.value.rsplit('_', 2)[0].replace('_', '').lower()
        self.ip_manager = IPAccessManager()

    def run(self, repo: DetectionRepo, stats_repo: BruteForceRepo) -> None:
        if not self.enabled or not exists(self.log_file_path):
            return
        self.repo = repo
        self.stats_repo = stats_repo
        command = self.get_logs_command.format(from_date=self.previous_log_timestamp, file_path=self.log_file_path)
        response = self.run_terminal_command(command)
        logs = response.split('\n')
        if len(logs) <= 1:
            # No failed or new login attempts detected.
            return
        if self.previous_log_timestamp:
            logs = logs[1:]
        self.previous_log_timestamp = self.get_previous_log_timestamp(logs[-1])
        self.parse_logs(logs)

    def parse_logs(self, logs: list) -> None:
        for log in logs:
            ip = self.get_ip(log)
            if not ip:
                continue
            timestamp = self.get_log_timestamp(log)
            port = self.get_port(log)
            login_attempts = self.get_log_attempts_number(log)

            self.parsed_logs.setdefault(ip, IPInfo(ip))
            self.parsed_logs[ip].attempts_number += login_attempts
            self.parsed_logs[ip].timestamps.append(timestamp)
            self.parsed_logs[ip].ports_attempted.add(port)

            if self.repo:
                self.add_to_detections_table(timestamp, ip, self.parsed_logs[ip].attempts_number, port)
            if self.stats_repo:
                self.add_to_brute_force_stats(ip, login_attempts)

            # If attempts number per addres reached limit then ip should be blocked.
            if self.parsed_logs[ip].attempts_number >= self.attempt_limit:
                self.parsed_logs[ip].suspicious_address = True
                # self.ip_manager.block_access_from_ip(ip)

    def add_to_detections_table(self, timestamp: datetime, source_ip: str, attempt_number: int, port: str):
        detection = Detection(
            detection_time=timestamp,
            attacker_ip_address=source_ip,
            module_name=self.name,
            note=f'Attacked port: {port}, attempt number: {attempt_number}'
        )
        self.repo.add(detection)

    def add_to_brute_force_stats(self, source_ip: str, new_attempts: int):
        valid = self.stats.check_validity()
        if not valid:
            mean = self.stats.calc_mean()
            empty_windows = self.stats.forward(datetime.now())
            up_to_now_stats = [BruteForcePersistentStats(id=None, time_window=tw) for tw in empty_windows]
            up_to_now_stats.insert(0, mean)
            self.stats_repo.add_many(up_to_now_stats)

        login_attempt_stats = BruteForceStats(new_attempts)
        self.stats.plus(source_ip, login_attempt_stats)

    def get_most_recent_log_timestamp(self):
        latest_log = self.repo.get_all(1, 0, f"module_name='{self.name.value}'", 'DESC')
        if not latest_log:
            return ''
        return latest_log[0].detection_time.strftime(self.timestamp_format)

    def get_previous_log_timestamp(self, log: str) -> str:
        return self.get_log_timestamp(log).strftime(self.timestamp_format)

    @staticmethod
    def run_terminal_command(command: str) -> str:
        pipe = Popen(command, shell=True, stdout=PIPE, stderr=PIPE, encoding="utf-8")
        response, error = pipe.communicate()
        if error:
            raise SyntaxError(error)

        return response.strip()

    @staticmethod
    def get_log_attempts_number(log: str) -> int:
        if 'message repeated' in log:
            attempts_number = int(findall(r'[0-9]+ times', log)[0].split()[0])
        else:
            attempts_number = 1

        return attempts_number

    @staticmethod
    def __check_os():
        _os = system()
        if _os != 'Linux':
            raise OSError(ErrorMessages.INVALID_OS_MSG.value.format(_os=_os))

    @staticmethod
    @abstractmethod
    def get_log_timestamp(log: str) -> datetime:
        pass

    @staticmethod
    @abstractmethod
    def get_ip(log: str) -> str:
        pass

    @staticmethod
    @abstractmethod
    def get_port(log: str) -> str:
        pass

