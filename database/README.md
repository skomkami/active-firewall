You need to have docker installed on your host.
To run docker image with .sql file binding:

To run docker image with `.sql` file binding:

<!--
```bash
docker run --rm -it --name postgres -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=active_firewall -d postgres
``` -->

```bash
docker run --rm -it --name postgres -p 5432:5432 -e POSTGRES_DB=active_firewall -e POSTGRES_PASSWORD=postgres -v $(pwd)/entry-points/db.sql:/docker-entrypoint-initdb.d/db.sql -d postgres
```

```bash
docker kill postgres
```

To enter database:

```bash
docker exec -it postgres psql -U postgres active_firewall
```
