from re import findall
from subprocess import check_output, CalledProcessError
from typing import Optional
from time import sleep


class LogAnalyzer:
    log_file_path = '/var/log/auth.log'
    command_1 = "cat /var/log/auth.log | grep -a 'Failed password for'"
    command_2_template = "awk '/^{from_date}.*/,/$1>=start/' {file_path} | grep -a 'Failed password for'"
    default_ip_info = {
        'attempts_number': 0,
        'dates': [],
        'suspicious_address': False
    }

    def __init__(self):
        self.parsed_logs = dict()
        self.delay = 2

    @staticmethod
    def run_command(command: str) -> Optional[str]:
        try:
            response = check_output(command, shell=True, encoding="utf-8").strip()
        except CalledProcessError:
            # No failed SSH login attempts detected.
            response = ''

        return response

    @staticmethod
    def get_log_date(log: str) -> str:
        return ' '.join(log.split()[0:3])

    def parse_logs(self, logs: list, new_logs: bool = True):
        for log in logs:
            [ip] = findall(r'[0-9]+(?:\.[0-9]+){3}', log)
            self.parsed_logs.setdefault(ip, self.default_ip_info)
            self.parsed_logs[ip]['attempts_number'] += 1
            self.parsed_logs[ip]['dates'].append(self.get_log_date(log))

    def run(self) -> None:
        previous_log_date = None
        command = self.command_1
        while True:
            if previous_log_date:
                command = self.command_2_template.format(from_date=previous_log_date, file_path=self.log_file_path)
            response = self.run_command(command)
            logs = response.split('\n')
            if len(logs) <= 1:
                # No failed SSH login attempts detected.
                sleep(self.delay)
                continue
            if previous_log_date:
                logs = logs[1:]
            previous_log_date = self.get_log_date(logs[-1])
            self.parse_logs(logs)
            print(self.parsed_logs)
            sleep(self.delay)

"""
cat /var/log/auth.log | grep -a 'Failed password for' -> 'Failed password for {user} from {ip} port {port} ssh2'
awk '/^Nov 22 12:52:34.*/,/Nov 24 20:41:06.*/' /var/log/auth.log | grep -a 'Failed password for'
awk '/^Nov 24 22:06:34.*/,/$1>=start/' /var/log/auth.log | grep -a 'Failed password for'

"""
