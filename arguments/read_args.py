import argparse


def getArgs():
  ap = argparse.ArgumentParser()

  ap.add_argument("-f", "--config-file", required=False, help="Config file path")

  args = vars(ap.parse_args())
  return args
