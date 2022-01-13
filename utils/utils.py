def debug(str: str):
  fileName = "test.txt"
  with open(fileName, 'a') as file:
      file.write(str)
      file.write('\n')