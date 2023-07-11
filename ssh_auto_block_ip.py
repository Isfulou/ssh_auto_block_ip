#! /usr/bin/env/ python3

import re
import subprocess
import time

# logFile安全日志
logFile = "/var/log/secure"

# 黑名单
hostDeny = "/etc/hosts.deny"

# 账号错误阈值
userErrNum = 3

# 密码错误次数阈值
pwdErrNum = 5


# 获取已经加入黑名单的ip,转换为字典
def getDenies():
    deniedDict = {}
    list = open(hostDeny).readlines()
    for ip in list:
        group = re.search(r"(\d+\.\d+\.\d+\.\d+)", ip)
        if group:
            deniedDict[group] = "1"
    return deniedDict

# 监控方法
def monitorLog(Logfile):
    # 读取安全日志
    popen = subprocess.Popen("tail -f "+logFile, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # 获取到已经在黑名单中的IP
    deniedDict = getDenies()
    # 统计账号错误次数
    userIp = {}

    # 统计密码错误的次数
    passIp = {}

    # 监控日志
    while True:
        # 每个0.1s进行一次刷新,减少cpu消耗
        time.sleep(0.1)
        # 将内容读取出来
        line = popen.stdout.readline().strip()
        if line:
            # 用户不存在的情况,正则表达匹配ip
            group = re.search("Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)", str(line))
            if group:
                # 统计账户错误次数
                if not userIp.get(group[1]):
                    userIp[group[1]] = 1
                else:
                    userIp[group[1]] = userIp[group[1]] + 1



                if userIp[group[1]] > userErrNum and not deniedDict.get(group[1]):
                    del userIp[group[1]]
                    subprocess.getoutput("echo sshd:{} >> {}".format(group[1], hostDeny))
                    deniedDict[group[1]] = "1"
                    time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                    print("{} --- add ip:{} to hosts.deny for invalid user".format(time_str, group[1]))
                    continue

            # 用户名合法,但是密码错误次数过多
            group = re.search("Failed password for \w+ from (\d+\.\d+\.\d+\.\d+)", str(line))
            if group:
                # 统计ip错误的次数
                if not passIp.get(group[1]):
                    passIp[group[1]] = 1
                else:
                    passIp[group[1]] = passIp[group[1]] + 1

                # 错误次数大于阈值直接封禁
                if passIp[group[1]] > pwdErrNum and not deniedDict.get(group[1]):
                    del passIp[group[1]]
                    subprocess.getoutput("echo sshd:{} >> {}".format(group[1], hostDeny))
                    deniedDict[group[1]] = "1"
                    time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
                    print("{} --- add ip:{} to hosts.deny for Failed password".format(time_str, group[1]))
                    continue

if __name__ == "__main__":
    monitorLog(logFile)
