In order to install all dependencies required run command posted down below in terminal.

```bash
pip install -r requirements.txt
```

Usage:
```bash
python3 run.py [-f path_to_config_file]
```
To run nginx container (for dos attack testing)
```bash
docker run --name some-nginx -d -p 80:80 nginx
```