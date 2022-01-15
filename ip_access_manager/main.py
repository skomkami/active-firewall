from manager import IPAccessManager
from time import sleep


def main() -> None:
    access_manager = IPAccessManager()
    ip = '192.168.0.3'
    access_manager.block_access_from_ip(ip)
    print('Blocked')
    # sleep(3)
    # access_manager.allow_access_from_ip(ip)
    # print('Allowed')
    # print('Done!')


if __name__ == '__main__':
    main()
