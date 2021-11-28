from enum import Enum
import jsonpickle
import json
from copy import deepcopy

class PeriodicityUnit(Enum):
    Second = 'Second'
    Minute = 'Minute'
    Hour = 'Hour'
    Day = 'Day'

class Periodicity(object):
    unit = PeriodicityUnit.Minute
    multiplier = 1

class DoSModuleConf(object):
    enabled = True
    maxPackets = 1000
    maxDataKB = 1000
    periodicity = Periodicity()

class BruteForceModuleConf(object):
    enabled = True
    maxTriesPerAddress = 100
    maxTriesTotal = 10000
    periodicity = Periodicity()

class PortScannerModuleConf(object):
    enabled = True
    blockAfterTries = 3

class AppConfig(object):
    dosModuleConf = DoSModuleConf()
    bfModuleConf = BruteForceModuleConf()
    portScannerConf = PortScannerModuleConf()

def readConf(path = 'config.json') -> AppConfig:
    #handle changed path to config file
    #default location is ./config.json
    #jsonpickle requires type informations so we need to inject them into config
    configTypesInfoDict = {
        "py/object": "config.config.AppConfig", 
        "dosModuleConf": {"py/object": "config.config.DoSModuleConf"}, 
        "bfModuleConf": {"py/object": "config.config.BruteForceModuleConf"},
        "portScannerConf": {"py/object": "config.config.PortScannerModuleConf"}
    }
    try:
        with open(path, 'r') as file:
            dictionary = json.load(file)
            enrichedDict = dict_of_dicts_merge(configTypesInfoDict, dictionary)  # python >= 3.5 <3.9 : {**dictionary, **configTypesInfoDict}
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