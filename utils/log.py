def log_to_file(str: str):
  fileName = "firewall.log"
  with open(fileName, 'a') as file:
    print(str, file=file)
