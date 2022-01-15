In order to install all dependencies required run command posted down below in terminal.

```bash
pip install -r requirements.txt
```

This app uses postgres database. In order to run one using docker you can use command:

```bash
docker run --rm -it --name postgres -p 5432:5432 -e POSTGRES_DB=active_firewall -e POSTGRES_PASSWORD=postgres -v $(pwd)/entry-points/db.sql:/docker-entrypoint-initdb.d/db.sql -d postgres
```
---
**NOTE**

You should run command from `database` directory or properly set path in `-v`(use volumes) option.
Database configuration can be set in config file.

---

Usage:
```bash
python3 run.py [-f path_to_config_file]
```

Example configuration can be seen in `config.json` file. If no path specified this file will be used as default.