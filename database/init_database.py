import psycopg2
from config import config


def create_tables():
    """ create tables in the PostgreSQL database"""
    commands = (
        """
        CREATE TABLE modules (
            module_id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL
        )
        """,
        """
        CREATE TABLE suspicious_ip_addresses (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(255) NOT NULL,
            timestamp TIMESTAMP,
            module_id INTEGER NOT NULL,
            FOREIGN KEY (module_id)
                REFERENCES modules (module_id)
                ON UPDATE CASCADE ON DELETE CASCADE
        )
        """
        )

    conn = None
    try:
        # read the connection parameters
        params = config()

        # connect to the PostgreSQL server
        conn = psycopg2.connect(**params)

        # create a new cursor
        cur = conn.cursor()

        # create table one by one
        for command in commands:
            cur.execute(command)

        # close communication with the PostgreSQL database server
        cur.close()

        # commit the changes
        conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()


def insert_data(modules_names, mock_ip_addressess):
    sql_modules = "INSERT INTO modules(name) VALUES(%s)"
    sql_ip_addresses = """
        INSERT INTO suspicious_ip_addresses(
            ip_address,
            timestamp,
            module_id
        ) VALUES (
            %s, 
            CURRENT_TIMESTAMP, 
            floor(random() * (SELECT MAX(module_id) FROM modules) + 1)::int
        )
        """
    conn = None
    try:
        # read database configuration
        params = config()

        # connect to the PostgreSQL database
        conn = psycopg2.connect(**params)

        # create a new cursor
        cur = conn.cursor()

        # execute the INSERT statements
        cur.executemany(sql_modules, modules_names)
        cur.executemany(sql_ip_addresses, mock_ip_addressess)

        # commit the changes to the database
        conn.commit()

        # close communication with the database
        cur.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()


if __name__ == '__main__':
    create_tables()

    modules_names = [
        ('DoS attacks',),
        ('port scanning detection',),
        ('brute force/dictionary attacks',)
    ]
    mock_ip_addressess = [
        ('192.168.2.109',),
        ('192.168.100.139',),
        ('168.2.2.89',),
        ('192.168.2.80',),
        ('192.168.2.200',),
    ]
    insert_data(modules_names, mock_ip_addressess)