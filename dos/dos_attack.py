import requests

url = 'http://localhost:80/'
for i in range(200):
    r = requests.get(url)