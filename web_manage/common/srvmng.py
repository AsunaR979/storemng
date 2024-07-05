
import configparser
import os
import re
import subprocess
import traceback
from venv import logger
from web_manage.common.cmdutils import run_cmd

from web_manage.common.errcode import get_error_result


def reload_service(service_name):
    try:
        cmd = "systemctl reload %s" % service_name
        (status, output) = run_cmd(cmd)
        if status != 0:
            return False
        return True
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))
        return False

def start_service(service_name):
    try:
        cmd = "systemctl start %s" % service_name
        (status, output) = run_cmd(cmd)
        if status != 0:
            return False
        return True
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))
        return False

# 关闭服务
def stop_service(service_name):
    try:
        cmd = "systemctl stop %s" % service_name
        (status, output) = run_cmd(cmd)
        if status != 0:
            return False
        return True
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))
        return False

# 重启服务
def restart_service(service_name):
    try:
        cmd = "systemctl restart %s" % service_name
        (status, output) = run_cmd(cmd)
        if status != 0:
            return False
        return True
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))
        return False

# 设置服务开机启动
def enable_service(service_name):
    try:
        cmd = "systemctl enable %s" % service_name
        (status, output) = run_cmd(cmd)
        if status != 0:
            return False
        return True
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))
        return False

# 禁用开机启动
def disable_service(service_name):
    try:
        cmd = "systemctl disable %s" % service_name
        (status, output) = run_cmd(cmd)
        if status != 0:
            return False
        return True
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))
        return False 

# 获取服务状态:{"name": service_name, "status": "running", "enabled": False}
def get_service_status(service_name):
    try:
        result = subprocess.run(['systemctl', 'status', service_name], capture_output=True, text=True)
        output = result.stdout
        resp = {"name": service_name, "status": "Unknown", "enabled": False}

        # 解析开机加载状态
        match = re.search(r'Loaded: .+\; (.+)\;', output)
        if match:
            bootload_status = match.group(1).strip()
            resp["enabled"] = True if bootload_status == "enabled" else False

        # 解析运行状态
        match = re.search(r'Active: .+\((.+)\)', output)
        if match:
            running_status = match.group(1).strip()
            resp["status"] = running_status
        return resp
    except Exception as err:
        logger.error(err)
        logger.error(''.join(traceback.format_exc()))