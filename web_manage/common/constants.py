import os

# Binary kilo unit
Ki = 1024
# Binary mega unit
Mi = Ki ** 2

Gi = Ki ** 3

# BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DEFAULT_PORT = 50004
# system volume group
SYS_VOLUME_GROUP = 'klas'
SYS_DEVICE_PATH = '/dev/sda'

# 心跳的组播地址
HEARTBEAT_IP = '224.0.0.88'
# 双控心跳配置路径
DOUBLE_CONTROL_CONFIG_PATH = '/etc/keepalived/'
DOUBLE_CONTROL_LOG_PATH = '/root/manage/log/'
# 双控心跳配置文件
HEARTBEAT_CONFIG_FILE_PATH = '/etc/keepalived/keepalived.conf'
# 复制逻辑卷配置路径
COPY_LV_CONFIG_PATH = '/usr/local/etc/drbd.d/'
# 复制逻辑卷端口端
COPY_LV_PORTS = '7789,7800'

# nfs配置文件
NFS_CONFIG_FILE = '/etc/exports'

# tgtd配置文件
TGTD_CONFIG_FILE_PATH = '/etc/tgt/conf.d/'

# nic bond
BOND_MASTERS = "/sys/class/net/bonding_masters"
BOND_SLAVES = "/sys/devices/virtual/net/%s/bonding/slaves"
BOND_INFO_DIR = "/proc/net/bonding"

# 监控服务的列表
MONITOR_SERVICES = ["storemng", "smb", "nfs", "vsftpd", "tgtd", "iscsid", "chronyd", "mariadb"]

# NTP配置文件
NTP_CONFIG_FILE = "/etc/chrony.conf"
# 系统时区设置目录
TIMEZONE_PATH = "/usr/share/zoneinfo/"
# 本地时间链接文件
LOCALTIME_LINK_FILE = "/etc/localtime"

EDUCATION_TYPE = 1
PERSONAL_TYPE = 2
LOG_FILE_PATH = '/var/log/storesys/'
LOG_DOWN_PATH = '/var/log/storesys/log_down'

MAX_THREADS = 8

SHUTDOWN_TIMEOUT = 90
