# server.py
import hashlib
import math
import operator
import random  # 提供随机数
import socket  # 提供套接字
import string
import sys
import threading

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


def get_session_key(clientsocket, addr):
    try:
        prime_num_DH = get_primes()  # 获取一个大素数
        generator_DH = get_generator(prime_num_DH)  # 获取该大素数的原根
        host_private_DH = random.randint(0, prime_num_DH-1)  # 设置私钥
        host_public_DH = get_cal(
            generator_DH, prime_num_DH, host_private_DH)  # 设置公钥

        # print("大素数："+str(prime_num_DH))
        # print("原根："+str(generator_DH))
        # print("服务器公钥："+str(host_public_DH))

        clientsocket.sendall(
            bytes(str(prime_num_DH), encoding="utf-8"))  # 发送给客户端
        clientsocket.sendall(bytes(str(generator_DH), encoding="utf-8"))
        clientsocket.sendall(bytes(str(host_public_DH), encoding="utf-8"))
        # 接收客户端公钥
        client_public_DH = int(
            str(clientsocket.recv(1024), encoding="utf-8"))  # 接收客户端的公钥
        # 生成会话密钥
        session_key = get_key(
            host_private_DH, client_public_DH, prime_num_DH)  # 生成会话密钥
        # 检验会话密钥是否够8位
        session_key = list(str(session_key))
        while(len(session_key) % 8 != 0):
            session_key.append("0")
        session_key = "".join(session_key)
        # 将套接字和会话密钥组合保存便于接收一方消息后解密再加密再传送给另一方
        temp_list = []
        temp_list.append(clientsocket)
        temp_list.append(session_key)
        clientsockets_session_key.append(tuple(temp_list))
        # 生成随机消息并发送给客户端
        ran_str = ''.join(random.sample(
            string.ascii_letters + string.digits, 24))
        # print("随机消息："+ran_str)
        obj_des = des(str(session_key), CBC, "\0\0\0\0\0\0\0\0",
                      pad=None, padmode=PAD_PKCS5)
        ran_secret = obj_des.encrypt(ran_str)  # decrypt
        clientsocket.send(bytes(ran_str, encoding="utf-8"))
        # 收到客户端对随机消息的加密判断会话密钥是否一致
        client_ran_secret = clientsocket.recv(1024)
        if(operator.eq(client_ran_secret, ran_secret)):
            print("%s会话密钥相同，身份验证成功！" % str(addr))
            clientsocket.send(bytes("1", encoding="utf-8"))
        else:
            clientsocket.send(bytes("0", encoding="utf-8"))
            return 0
        # print("开始加密通话")
        while True:
            # 接收到的客户端的消息
            temp_mess = clientsocket.recv(1024)
            en_mess = obj_des.decrypt(temp_mess)
            en_mess = str(en_mess, encoding="utf-8")
            if(en_mess == "exit()"):
                return 0
            # 将解密的消息与发送源地址链接起来保存等待加密后发给另外的客户端
            temp_str = ""
            temp_str += addr[0]
            temp_str += "["
            temp_str += str(addr[1])
            temp_str += "]:  "
            temp_str += en_mess
            messages_addr.append(temp_str)
    except ConnectionResetError:
        print("一个客户端意外退出")


clientsockets_session_key = []
messages_addr = []
# 获取本机host
port = 9999

# 生成套接字对象并绑定地址侦听
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.bind(("127.0.0.1", port))
serversocket.listen(5)


# 复读机线程。用于将所有客户端的消息再转发给所有客户端
def repetition():
    while True:
        for i in messages_addr:
            for c in clientsockets_session_key:
                obj_des_temp = des(str(c[1]), CBC, "\0\0\0\0\0\0\0\0",
                                   pad=None, padmode=PAD_PKCS5)
                en_mess = obj_des_temp.encrypt(i)
                c[0].send(en_mess)
            messages_addr.remove(i)


if __name__ == '__main__':
    # 复读机单独线程
    repetition = threading.Thread(target=repetition)
    repetition.start()
    while True:
        # 接收到客户端连接请求后创建新线程
        clientsocket, addr = serversocket.accept()
        if clientsocket == False:
            break
        print("已启动%d个线程" % len(clientsockets_session_key))
        clients = threading.Thread(
            target=get_session_key, args=(clientsocket, addr))
        clients.start()