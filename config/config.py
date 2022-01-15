import json
from copy import deepcopy
from enum import Enum

import jsonpickle


class PeriodicityUnit(Enum):
    Second = 'Second'
    Minute = 'Minute'
    Hour = 'Hour'
    Day = 'Day'


class Periodicity:
    unit = PeriodicityUnit.Minute
    multiplier = 1

    def seconds(self):
        unit_to_seconds = 1
        if self.unit == PeriodicityUnit.Minute:
            unit_to_seconds = 60
        elif self.unit == PeriodicityUnit.Hour:
            unit_to_seconds = 60 * 60
        elif self.unit == PeriodicityUnit.Day:
            unit_to_seconds = 60 * 60 * 24
        return unit_to_seconds * self.multiplier


class ServiceConfig:
    enabled = True
    attemptLimit = 100


class Services:
    ssh = ServiceConfig()
    apache2 = ServiceConfig()
    imappop3 = ServiceConfig()
    available_services = {
        'ssh': ssh,
        'apache2': apache2,
        'imappop3': imappop3
    }

    def __iter__(self):
        for name, service in self.available_services.items():
            yield name, service


class DBConnectionConf:
    host = 'localhost'
    host_ip = '127.0.0.1'
    user = 'postgres'
    dbname = 'active_firewall'
    password = 'postgres'
    port = 5432

class DoSModuleConf:
    enabled = True
    maxPackets = 1000
    maxDataKB = 1000
    periodicity = Periodicity()


class BruteForceModuleConf:
    frequency = 100
    periodicity = Periodicity()
    services = Services()


class PortScannerModuleConf:
    enabled = True
    blockAfterTries = 3
    lanIp = "127.0.0.1"
    periodicity = Periodicity


class AppConfig:
    dbConnectionConf = DBConnectionConf()
    dosModuleConf = DoSModuleConf()
    bfModuleConf = BruteForceModuleConf()
    portScannerConf = PortScannerModuleConf()


def readConf(path='config.json') -> AppConfig:
    # handle changed path to config file
    # default location is ./config.json
    # jsonpickle requires type informations so we need to inject them into config
    configTypesInfoDict = {
        "py/object": "config.config.AppConfig",
        "dbConnectionConf": {"py/object": "config.config.DBConnectionConf"},
        "dosModuleConf": {
            "py/object": "config.config.DoSModuleConf",
            "periodicity": {"py/object": "config.config.Periodicity"}
        },
        "bfModuleConf": {
            "py/object": "config.config.BruteForceModuleConf",
            "periodicity": {"py/object": "config.config.Periodicity"},
            "services": {
                "py/object": "config.config.Services",
                "ssh": {"py/object": "config.config.Service"},
                "apache2": {"py/object": "config.config.Service"},
                "imappop3": {"py/object": "config.config.Service"}
            }
        },
        "portScannerConf": {
            "py/object": "config.config.PortScannerModuleConf",
            "periodicity": {"py/object": "config.config.Periodicity"}
        }
    }
    try:
        with open(path, 'r') as file:
            dictionary = json.load(file)
            enrichedDict = dict_of_dicts_merge(configTypesInfoDict,
                                               dictionary)  # python >= 3.5 <3.9 : {**dictionary, **configTypesInfoDict}
            enrichedJson = json.dumps(enrichedDict)
            return jsonpickle.decode(enrichedJson)
    except FileNotFoundError:
        return AppConfig()


def dict_of_dicts_merge(x, y):
    z = {}
    overlapping_keys = x.keys() & y.keys()
    for key in overlapping_keys:
        z[key] = dict_of_dicts_merge(x[key], y[key])
    for key in x.keys() - overlapping_keys:
        z[key] = deepcopy(x[key])
    for key in y.keys() - overlapping_keys:
        z[key] = deepcopy(y[key])
    return z
