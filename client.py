# client.py
import random
import socket
import string
import hashlib
import time
import threading
import getpass

from pyDes import *


def get_generator(p):
    # 获取一个原根
    # 素数必存在至少一个原根
    # g^(p-1) = 1 (mod p)当且仅当指数为p-1的时候成立
    a = 2
    while 1:
        if a**(p-1) % p == 1:
            num = 2
            mark = 0
            while num < p-1:
                if a**num % p == 1:
                    mark = 1
                num += 1
        if mark == 0:
            return a
        a += 1


def get_cal(a, p, rand):
    # 获得计算数
    cal = (a**rand) % p
    return cal


def get_key(cal_A, cal_B, p):
    # 获得密钥
    key = (cal_B ** cal_A) % p
    return key


# 生成一个奇数生成器。
def odd_iter():
    n = 1
    while True:
        n = n + 2
        yield n


# 过滤掉n的倍数的数。
def not_divisible(n):
    return lambda x: x % n > 0


# 获取当前序列的第一个元素，然后删除后面序列该元素倍数的数，然后构造新序列。
def primes():
    yield 2
    it = odd_iter()
    while True:
        n = next(it)
        yield n
        it = filter(not_divisible(n), it)


# 获取 start 到 stop 之间的素数。
def get_primes():
    stop = random.randint(2000, 3000)
    nums = []
    for n in primes():
        if n < stop:
            nums.append(n)
        elif n > stop:
            return nums[-1]


port = 9999

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 生成客户端套接字对象
clientsocket.connect(("127.0.0.1", port))  # 链接服务器
host_prime_num_DH = int(clientsocket.recv(1024))  # 服务器生成的大素数
host_generator_DH = int(clientsocket.recv(1024))  # 服务器生成的大素数的原根
host_public_DH = int(clientsocket.recv(1024))  # 服务器的DH公钥

# print("大素数："+str(host_prime_num_DH))
# print("原根："+str(host_generator_DH))
# print("服务器公钥："+str(host_public_DH))

client_private_DH = random.randint(0, host_prime_num_DH-1)  # 生成客户端私钥
client_public_DH = get_cal(
    host_generator_DH, host_prime_num_DH, client_private_DH)  # 生成客户端公钥

session_key = get_key(client_private_DH, host_public_DH,
                      host_prime_num_DH)  # 生成会话密钥
# 检验会话密钥是否够8位
session_key = list(str(session_key))
while(len(session_key) % 8 != 0):
    session_key.append("0")
session_key = "".join(session_key)
# 发送自己的公钥给服务器
clientsocket.send(bytes(str(client_public_DH), encoding="utf-8"))
# 接收到服务器发来的随机消息使用会话密钥进行加密
ran_str = clientsocket.recv(1024)
# print("随机消息："+str(ran_str, encoding="utf-8"))
# 使用会话密钥DES加密
obj_des = des(session_key, CBC, "\0\0\0\0\0\0\0\0",
              pad=None, padmode=PAD_PKCS5)
ran_secret = obj_des.encrypt(ran_str)

# 将自己加密后的随机消息发送给服务器
clientsocket.send(ran_secret)
# 接收服务器对于会话密钥是否一致的判断
check_fin = int(str(clientsocket.recv(1024), encoding="utf-8"))
if(bool(check_fin)):
    print("会话密钥相同，身份验证成功！")
else:
    print("会话密钥不同，身份验证失败！")

print("开始加密通话")


# 将服务器传送的会话解密输出
def cat_room(clientsocket, obj_des):
    try:
        while True:
            messages = clientsocket.recv(1024)
            if messages:
                # print(str(messages, encoding="utf-8"))
                de_mess = obj_des.decrypt(messages)
                print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
                print(str(de_mess, encoding="utf-8"))
    except UnicodeDecodeError:
        pass


if __name__ == '__main__':
    # 聊天室单独一个线程处理
    cat_room = threading.Thread(
        target=cat_room, args=(clientsocket, obj_des))
    cat_room.start()
    while True:
        # 输入英文加密传输
        mess_to = getpass.getpass("")
        if(mess_to == "exit()"):
            break
        mess_to = list(mess_to)
        # 密文也是需要8的倍数位
        while(len(mess_to) % 8 != 0):
            mess_to.append("\0")
        mess_to = "".join(mess_to)
        encry_mess = obj_des.encrypt(mess_to)
        clientsocket.send(encry_mess)