from subprocess import Popen, PIPE
from enum import Enum

from utils.log import log_to_file


class ErrorMessages(Enum):
    PERMISSION_DENIED_MSG = 'Super user permissions are needed in order to access iptables.'


class IPAccessManager:

    def __init__(self):
        self.blocked_ips = set()

    @staticmethod
    def run_terminal_command(command: str) -> None:
        pipe = Popen(command, shell=True, stdout=PIPE, stderr=PIPE, encoding="utf-8")
        response, error = pipe.communicate()
        if 'Permission denied' in error:
            raise PermissionError(ErrorMessages.PERMISSION_DENIED_MSG.value)
        if error:
            raise SyntaxError(error)

    def block_access_from_ip(self, ip: str) -> None:
        if ip in ['localhost', '127.0.0.1']:
            log_to_file("Skipping blocking localhost")
            return
        command = f'iptables -I INPUT -s {ip} -j DROP'
        self.run_terminal_command(command)
        self.blocked_ips.add(ip)

    def allow_access_from_ip(self, ip: str) -> None:
        command = f'iptables -D INPUT -s {ip} -j DROP'
        self.run_terminal_command(command)
        self.blocked_ips.discard(ip)
