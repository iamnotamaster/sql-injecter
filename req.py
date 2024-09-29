import requests
import time
# payload ： 参数列表
# url
# expected_data ： 期待的返回结果 
def req_by_bool_get(payload, url, expected_data):
    rep = requests.get(url, params=payload)
    if expected_data in rep.text:
        return 1
    else:
        return 0

def req_by_bool_post(payload, url, expected_data):
    rep = requests.post(url, data=payload)
    # print(rep.text)
    # print(payload)
    if expected_data in rep.text:
        return 1
    else:
        return 0


# payload ： 参数列表
# url
# expected_time ： 期待等待的时间长短 
def req_by_time_get(payload, url, expected_time):
    earlier = time.time()
    rep = requests.get(url, params=payload)
    latter = time.time()
    if latter - earlier >= expected_time:
        return 1
    else:
        return 0
        
def req_by_time_post(payload, url, expected_time):
    earlier = time.time()
    rep = requests.post(url, data=payload)
    latter = time.time()
    if latter - earlier >= expected_time:
        return 1
    else:
        return 0

