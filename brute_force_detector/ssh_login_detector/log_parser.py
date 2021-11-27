from re import findall
from dataclasses import dataclass, field
from enum import Enum
from subprocess import Popen, PIPE
from platform import system
from time import sleep


class ErrorMessages(Enum):
    INVALID_OS_MSG = 'Log parser is not able to be ran on {_os} system.'


class LinuxParameters(Enum):
    LOG_FILE_PATH = '/var/log/auth.log'
    GET_LOGS_COMMAND = "awk '/^{from_date}.*/,/$1>=start/' {file_path} | grep -a 'Failed password for'"


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
               f'Timestamps of attempts: {", ".join(self.timestamps)}\n' \
               f'Ports attacked: {", ".join(self.ports_attempted)}\n' \
               f'Address is suspicious: {"yes" if self.suspicious_address else "no"}\n'


class LogParser:

    def __init__(self, delay: float = 0.5):
        self.delay = delay
        self.parsed_logs = dict()
        self.log_file_path, self.get_logs_command = self.get_path_and_command()

    @staticmethod
    def get_path_and_command() -> tuple[str, str]:
        _os = system()
        if _os == 'Linux':
            parameters = LinuxParameters
        else:
            raise OSError(ErrorMessages.INVALID_OS_MSG.value.format(_os=_os))

        return parameters.LOG_FILE_PATH.value, parameters.GET_LOGS_COMMAND.value

    @staticmethod
    def run_terminal_command(command: str) -> str:
        pipe = Popen(command, shell=True, stdout=PIPE, stderr=PIPE, encoding="utf-8")
        response, error = pipe.communicate()
        if error:
            raise SyntaxError(error)

        return response.strip()

    @staticmethod
    def get_log_timestamp(log: str) -> str:
        return ' '.join(log.split()[0:3])

    @staticmethod
    def get_log_port(log: str) -> str:
        return log.split()[-2]

    @staticmethod
    def get_log_attempts_number(log: str) -> int:
        if 'message repeated' in log:
            attempts_number = int(findall(r'[0-9]+ times', log)[0].split()[0])
        else:
            attempts_number = 1

        return attempts_number

    def parse_logs(self, logs: list) -> None:
        for log in logs:
            [ip] = findall(r'[0-9]+(?:\.[0-9]+){3}', log)
            self.parsed_logs.setdefault(ip, IPInfo(ip))
            self.parsed_logs[ip].attempts_number += self.get_log_attempts_number(log)
            self.parsed_logs[ip].timestamps.append(self.get_log_timestamp(log))
            self.parsed_logs[ip].ports_attempted.add(self.get_log_port(log))

    def run(self) -> None:
        previous_log_timestamp = ''
        while True:
            command = self.get_logs_command.format(from_date=previous_log_timestamp, file_path=self.log_file_path)
            response = self.run_terminal_command(command)
            logs = response.split('\n')
            if len(logs) <= 1:
                # No failed or new SSH login attempts detected.
                sleep(self.delay)
                continue
            if previous_log_timestamp:
                logs = logs[1:]
            previous_log_timestamp = self.get_log_timestamp(logs[-1])
            self.parse_logs(logs)
            sleep(self.delay)
