from re import findall
from dataclasses import dataclass, field
from subprocess import check_output, CalledProcessError

from typing import Optional
from time import sleep


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
    log_file_path = '/var/log/auth.log'
    init_command = "cat /var/log/auth.log | grep -a 'Failed password for'"
    default_command = "awk '/^{from_date}.*/,/$1>=start/' {file_path} | grep -a 'Failed password for'"

    def __init__(self):
        self.parsed_logs = dict()
        self.delay = 0.5

    @staticmethod
    def run_terminal_command(command: str) -> Optional[str]:
        try:
            response = check_output(command, shell=True, encoding="utf-8").strip()
        except CalledProcessError:
            # Command did not return anything.
            response = ''

        return response

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

    def parse_logs(self, logs: list):
        for log in logs:
            [ip] = findall(r'[0-9]+(?:\.[0-9]+){3}', log)
            self.parsed_logs.setdefault(ip, IPInfo(ip))
            self.parsed_logs[ip].attempts_number += self.get_log_attempts_number(log)
            self.parsed_logs[ip].timestamps.append(self.get_log_timestamp(log))
            self.parsed_logs[ip].ports_attempted.add(self.get_log_port(log))

    def run(self) -> None:
        previous_log_timestamp = None
        command = self.init_command
        while True:
            if previous_log_timestamp:
                command = self.default_command.format(from_date=previous_log_timestamp, file_path=self.log_file_path)
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
