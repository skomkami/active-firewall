from paramiko import SSHClient, AutoAddPolicy, AuthenticationException


TARGET_IP = 'VALID_IP'
USERNAME = 'VALID_USERNAME'
PASSWORD = 'INVALID_PASSWORD'
TRIES_NUMBER = 10


def main():
    ssh_client = SSHClient()
    ssh_client.load_system_host_keys()
    ssh_client.set_missing_host_key_policy(AutoAddPolicy())
    for i in range(TRIES_NUMBER):
        try:
            ssh_client.connect(hostname=TARGET_IP, username=USERNAME, password=PASSWORD, look_for_keys=False)
        except AuthenticationException:
            print(f'\nFailed authentication for {i + 1} time')


if __name__ == '__main__':
    main()
