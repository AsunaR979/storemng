import traceback
import logging
import inspect
from functools import wraps
from web_manage.admin import models as log_model


logger = logging.getLogger(__name__)


def insert_operation_log(msg, result, log_user=None, module="default"):
    if log_user is None:
        uid = None
        uname = "admin"
        user_ip = ''
    else:
        uid = log_user["id"]
        uname = log_user["user_name"]
        user_ip = log_user["user_ip"]
    values = {
        "user_id": uid,
        "user_name": uname,
        "user_ip": user_ip,
        "content": msg,
        "result": result,
        "module": module
    }
    log_model.OperationLog.objects.create(**values)


def operation_record(msg="", module="default"):
    """
    记录操作日志
    :param msg: 操作日志内容，如果操作日志中包含参数，则使用{参数名}格式的字符串，例如：
            添加名字{name}，
    :param module 表示是哪个模块
    :return:
    """
    def wrapper1(func):
        @wraps(func)
        def wrapper2(*args, **kwargs):
            arg_dict = inspect.getcallargs(func, *args, **kwargs)
            error = None
            ret = None
            result = '成功'
            try:
                ret = func(*args, **kwargs)
                if isinstance(ret, dict):
                    if not ret.get('code') == 0:
                        result = ret.get('msg', 'unknown error')
                else:
                    result = 'unknown error'
            except Exception as ex:
                result = str(ex)
                error = ex
                # logger.error("run func %s error:%s", func.__name__, ex, exc_info=True)
            if msg == "":
                logmsg = "Call {} {}".format(func.__name__, result)
            else:
                logmsg = msg.format(**arg_dict)
            user = arg_dict.get('log_user', None)
            if not user:
                req = arg_dict.get("request")
                if req:
                    user = dict()
                    user["id"] = req.user.id
                    user["user_name"] = req.user.username
                    user["user_ip"] = req.META.get('HTTP_X_FORWARDED_FOR') if req.META.get('HTTP_X_FORWARDED_FOR') \
                        else req.META.get("REMOTE_ADDR")
            try:
                insert_operation_log(logmsg, result, user, module)
            except:
                pass

            if error is not None:
                raise error
            return ret
        return wrapper2
    return wrapper1

