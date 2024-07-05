# -*- coding: utf-8 -*-
from copy import deepcopy

from storesys.settings import HOSTNAME


# 设置错误码
ERROR_CODE = {
    "Success": {"code": 0, "msg": "成功"},

    # 10001 ~ 10999 用户登录错误码
    "LoginFailError": {"code": 10001, "msg": "用户名或密码错误"},
    "UsernameError": {"code": 10002, "msg": "用户名错误"},
    "NotPasswordInputError": {"code": 10005, "msg": "请输入管理员密码"},
    "AdminUserNotExist": {"code": 10017, "msg": "管理员账号不存在"},
    "ActivationError": {"code": 10018, "msg": "激活失败"},


    #50000 ~ 50999为index模块错误码范围
    "GetOperatorLogError" : {"code" : 50000, "msg" : "获取操作日志页面失败"},
    "DeleteOperatorLogError" : {"code" : 50001, "msg" : "删除操作日志失败"},
    "CreateTmpDirError" : {"code" : 50002, "msg" : "创建临时目录失败"},
    "CopyRunLogToTmpDirError" : {"code" : 50003, "msg" : "拷贝运行日志到临时目录失败"},
    "TarTmpDirError" : {"code" : 50004, "msg" : "压缩临时目录失败"},
    "UnloadRunLogrError" : {"code" : 50005, "msg" : "卸载运行日志失败"},
    "DeleteRunLogrError" : {"code" : 50006, "msg" : "删除运行日志失败"},



    #60000 ~ 60999为告警模块错误码范围
    "QueryWranDatebaseOrLevelConfigError" : {"code" : 60000, "msg" : "查询告警数据库和告警级别配置文件失败"},
    "QueryWarnMailOrSmtpConfigError" : {"code" : 60001, "msg" : "查询告警邮箱数据库和smtp服务器配置文件失败"},
    "SetSmtpServerInfoError" : {"code" : 60002, "msg" : "设置Smtp服务器信息失败"},
    "AddMailError" : {"code" : 60003, "msg" : "添加邮箱失败"},
    "DeleteMailDataTableError" : {"code" : 60004, "msg" : "删除邮箱失败"},
    "GetWarnInfoError" : {"code" : 60005, "msg" : "获取通告信息失败"},
    "ModifyHadViewError" : {"code" : 60006, "msg" : "修改记录已查看标志失败"},
    "DeleteWarmTableRecordError" : {"code" : 60007, "msg" : "删除告警表信息失败！！！"},
    "TestMailError" : {"code" : 60008, "msg" : "测试邮箱功能失败！！！"},


    # 70000 ~ 70999 为系统管理模块错误码范围
    "ModifyNetworkInfoError" : {"code" : 70000, "msg" : "修改网络信息失败"},
    "RestartNetworkError" : {"code" : 70001, "msg" : "重启网络失败"},
    "HostnameCannotBeEmpty" : {"code" : 70002, "msg" : "主机名不能为空"},
    "SetHostnameError" : {"code" : 70003, "msg" : "设置主机名失败"},
    "AlreadyBindHost" : {"code" : 70004, "msg" : "双控管理中已经绑定对端主机，请先解绑"},
    "NicAlreadyUsedInHeartbeat" : {"code" : 70005, "msg" : "该网卡IP已经用于心跳，请先释放"},
    "NicAlreadyUsedInVip" : {"code" : 70006, "msg" : "该网卡IP已经用于双控的VIP，请先释放"},
    "NicAlreadyUsedInCopyLv" : {"code" : 70007, "msg" : "该网卡IP已经用于复制逻辑卷，请先释放"},
    "ConfigBondError" : {"code" : 70008, "msg" : "Bond配置失败"},
    "UnBondError" : {"code" : 70009, "msg" : "Bond解绑失败"},
    "IPUsedByOtherHost" : {"code" : 70010, "msg" : "IP已经被使用"},
    "NotPhysicalNICError" : {"code" : 70011, "msg" : "该网卡不是物理网卡"},
    "GetTimeZoneError" : {"code" : 70012, "msg" : "获取当前系统时区失败"},
    "GetNtpEnabledStatusError" : {"code" : 70013, "msg" : "获取NTP开启状态失败"},
    "GetNtpServersError" : {"code" : 70014, "msg" : "获取NTP服务器失败"},
    "StopNtpError" : {"code" : 70015, "msg" : "禁用网络时间同步失败"},
    "SyncSysClockError" : {"code" : 70016, "msg" : "同步系统时钟失败，请检查网络后重试"},
    "SyncHwClockError" : {"code" : 70017, "msg" : "同步硬件时钟失败"},
    "StartNtpError" : {"code" : 70018, "msg" : "启用网络时间同步失败"},
    "SetDateTimeError" : {"code" : 70019, "msg" : "设置日期时间失败"},
    "InvalidTimezone" : {"code" : 70020, "msg" : "无效时区（系统暂不支持该时区）"},
    "SetTimezoneError" : {"code" : 70021, "msg" : "设置时区失败"},
    "GetRouteInfoError" : {"code" : 70022, "msg" : "获取路由信息失败"},
    "NetworkNnreachable" : {"code" : 70023, "msg" : "网络不可达"},
    "MaskNotMarchAddress" : {"code" : 70024, "msg" : "子网掩码与路由地址不匹配"},
    "RouteAlreadyExist" : {"code" : 70025, "msg" : "路由已存在"},
    "NetCardNotExist" : {"code" : 70026, "msg" : "网卡设备不存在"},
    "AddTempRouteError" : {"code" : 70027, "msg" : "添加临时路由失败"},
    "DeleteTempRouteError" : {"code" : 70028, "msg" : "删除临时路由失败"},
    "RouteCfgVerifyError" : {"code" : 70029, "msg" : "路由配置验证失败"},
    "RouteCfgFileNotExist" : {"code" : 70030, "msg" : "路由配置文件不存在"},
    "EditRouteCfgFileError" : {"code" : 70031, "msg" : "编辑路由配置文件失败"},
    "UploadedFileNotSpec" : {"code" : 70032, "msg" : "上传的文件不符合规范"},
    "UploadFileError" : {"code" : 70033, "msg" : "上传文件失败"},
    "ReceiveFileError" : {"code" : 70034, "msg" : "接收文件失败"},
    "BackupSwError" : {"code" : 70035, "msg" : "当前版本备份失败"},
    "UnzipFileError" : {"code" : 70036, "msg" : "解压文件失败"},
    "CopyDateFileError" : {"code" : 70037, "msg" : "拷贝数据库文件失败"},
    "DeleteOldDirError" : {"code" : 70038, "msg" : "删除旧目录失败"},
    "RenameNewDirError" : {"code" : 70039, "msg" : "重命名新目录失败"},
    "RestartStoremngError" : {"code" : 70040, "msg" : "重启后台服务失败"},
    "StoremngException" : {"code" : 70041, "msg" : "后台服务异常，请联系管理员"},
    "NicAlreadyUsedInDoubleControl" : {"code" : 70042, "msg" : "该网卡已经用于主机绑定，无法修改"},
    "IpIsBeingUsed" : {"code":70043,"msg":"ip正在被使用"},
   
    # 70200 ~ 70300 为监控模块错误码范围
    "GetMonitorfoError" : {"code" : 70200, "msg" : "获取监控信息失败"},
    "GetCpuInfoError" : {"code" : 70201, "msg" : "获取cpu信息失败"},
    "GetMemoryInfoError" : {"code" : 70202, "msg" : "获取内存信息失败"},
    "GetDiskioInfoError" : {"code" : 70203, "msg" : "获取磁盘io信息失败"},
    "GetNetworkInfoError" : {"code" : 70204, "msg" : "获取网络速率信息失败"},
    "FillMonitorfoError" : {"code" : 70205, "msg" : "写入监控信息失败"},
    "FillCpuInfoError" : {"code" : 70206, "msg" : "写入CPU监控信息失败"},
    "FillMemoryInfoError" : {"code" : 70207, "msg" : "写入内存监控信息失败"},
    "FillDiskioInfoError" : {"code" : 70208, "msg" : "写入磁盘io监控信息失败"},
    "FillNetworkInfoError" : {"code" : 70209, "msg" : "写入网络速率监控信息失败"},
    "SettingMonitorError" : {"code" : 70210, "msg" : "修改监控设置失败"},
    "DeleteMonitorQuestError" : {"code" : 70211, "msg" : "删除监控任务失败"},
    "CreateMonitorQuestError" : {"code" : 70212, "msg" : "创建监控任务失败"},
    "EditMonitorDaysError" : {"code" : 70213, "msg" : "修改保存天数失败"},

    # 71000 ~ 71999 为双控模块错误码范围
    "GetHostnameError" : {"code" : 71000, "msg" : "获取主机名失败"},
    "DualControlServiceNotFound" : {"code" : 71001, "msg" : "找不到双控服务"},
    "StartDualControlServiceError" : {"code" : 71002, "msg" : "开启双控服务失败"},
    "StopDualControlServiceError" : {"code" : 71003, "msg" : "关闭双控服务失败"},
    "CopyLvResourceNotExist" : {"code" : 71004, "msg" : "复制逻辑卷资源不存在"},
    "CopyLvResourceNotStarted" : {"code" : 71005, "msg" : "复制逻辑卷资源未启动"},
    "GetCopyLvResourceRoleError" : {"code" : 71006, "msg" : "获取复制逻辑卷资源角色失败"},
    "ReloadDualControlServiceError" : {"code" : 71007, "msg" : "重载双控服务失败"},
    "UpdateVipError" : {"code" : 71008, "msg" : "更新虚拟IP失败"},
    "DualMachineResAlreadyExists" : {"code" : 71009, "msg" : "双机资源已经存在"},    
    "CurrentNodeNotHaveVip" : {"code" : 71010, "msg" : "当前节点没有VIP"},
    "CopyLvResRoleNotPrimary" : {"code" : 71011, "msg" : "复制逻辑卷资源角色不是主"},
    "OneHeartbeatOnePingNode" : {"code" : 71012, "msg" : "一条心跳线路只允许添加一个Ping节点资源"},
    "PeerNodeNotConnected" : {"code" : 71013, "msg" : "对端节点未连接"},
    "GetPeerHeartbeatDetailError" : {"code" : 71014, "msg" : "获取对端心跳线路详情失败"},
    "GetLocalHeartbeatDetailError" : {"code" : 71015, "msg" : "获取本地心跳线路详情失败"},
    "GrepCmdError" : {"code" : 71016, "msg" : "执行匹配指令失败"},
    "ExistsCopyLvResource" : {"code" : 71017, "msg" : "存在未删除的复制逻辑卷"},
    "ExistsHearbeatLineResource" : {"code" : 71018, "msg" : "存在未删除的心跳线路"},
    "DeviceNameAlreadyExists" : {"code" : 71019, "msg" : "禁止使用系统已存在的设备名"},
    "ExsitsHaResource" : {"code" : 71020, "msg" : "存在已启用双控管理的高可用资源，请先释放"},
    "TwoHostHadTheSameHostname" : {"code" : 71021, "msg" : "相同主机名机器禁止绑定"},
    "ExsitsClusterNodeData" : {"code" : 71022, "msg" : "禁止执行多次绑定，请先解绑"},
    "VipAlreadyExists" : {"code" : 71023, "msg" : "虚拟IP已经被使用，请更换其他IP地址"},
    "NetworkUnreachable" : {"code" : 71024, "msg" : "远端IP地址无法Ping通，请更换其他IP地址"},
    "HeartbeatInfoNotExists" : {"code" : 71025, "msg" : "心跳线路信息不存在"},


    # 72000 ~ 72999 为Raid模块错误码范围
    "GetRaidInfoListError" : {"code" : 72000, "msg" : "获取raid列表出错"},
    "ReMoveRaidError" : {"code" : 72001, "msg" : "删除raid出错"},
    "CreateRaidError" : {"code" : 72002, "msg" : "创建raid出错"},
    "GetFreeZoneError" : {"code" : 72003, "msg" : "获取空闲分区出错"},
    "GetRaidDetailError" : {"code" : 72004, "msg" : "获取raid详细信息出错"},
    "AddHostError" : {"code" : 72005, "msg" : "为raid添加热备盘出错"},
    "RemoveHostError" : {"code" : 72006, "msg" : "为raid删除热备盘出错"},
    "FaultyDevError" : {"code" : 72007, "msg" : "faulty raid 子设备出错"},
    "RecoverFaultyDevError" : {"code" : 72008, "msg" : "恢复 faulty raid 子设备出错"},
    "DeviceOrResourceBusy" : {"code" : 72015, "msg" : "恢复 faulty 设备失败， Device or resource busy"},
    "RemoveFaultyDevsError" : {"code" : 72009, "msg" : "删除 faulty raid 子设备出错"},
    "ReplaceChildDevsError" : {"code" : 72010, "msg" : "替换 raid 子设备出错"},
    "GrowUpRaidError" : {"code" : 72011, "msg" : "扩容 raid 出错"},
    "GetMailInfoError" : {"code" : 72012, "msg" : "获取邮箱信息出错"},
    "UpdateMailInfoError" : {"code" : 72013, "msg" : "更新邮箱信息出错"},
    "UpdateMailConfigError" : {"code" : 72014, "msg" : "更新邮箱配置出错"},
    "RemoveDevError" : {"code" : 72015, "msg" : "删除raid 子设备出错"},
    "getControllerInfoError" : {"code" : 72016, "msg" : "获取控制器信息出错"},
    "getPhysicalDiskInfoError" : {"code" : 72017, "msg" : "获取物理磁盘信息出错"},
    "getLogicDiskInfoError" : {"code" : 72018, "msg" : "获取逻辑磁盘信息出错"},
    "createHardRaidError" : {"code" : 72019, "msg" : "创建硬raid出错"},
    "DeleteHardRaidError" : {"code" : 72020, "msg" : "删除硬raid出错"},
    "SecureDeleteHardRaidError" : {"code" : 72021, "msg" : "安全移除硬raid出错"},
    "reScanError" : {"code" : 72022, "msg" : "重新扫描出错"},
    "ArrayCheckDataError" : {"code" : 72023, "msg" : "阵列校验出错"},
    "SetArrayStateError" : {"code" : 72024, "msg" : "设置阵列状态出错"},
    "SetArrayParaError" : {"code" : 72025, "msg" : "设置阵列参数出错"},
    "TransformArrayError" : {"code" : 72026, "msg" : "转换阵列出错"},
    "InitDiskError" : {"code" : 72027, "msg" : "磁盘初始化出错"},
    "AddSpareDiskError" : {"code" : 72028, "msg" : "添加热备盘出错"},
    "RemoveSpareDiskError" : {"code" : 72029, "msg" : "移除热备盘出错"},
    "InitHardRaidLibError" : {"code" : 72030, "msg" : "初始化硬raid库失败", "data":[]},
    "GetUniqueNumberError" : {"code" : 72031, "msg" : "获取控制器Pci唯一号信息失败 ！！！", "data":[]},
    "InconsistentNumberOfItemsError" : {"code" : 72032, "msg" : "控制器Pci唯一号个数与控制器个数不一致 ！！！", "data":[]},
    "ArrayCannotSafelyRemoved" : {"code" : 72033, "msg" : "阵列不可以安全移除 ！！！", "data":[]},
    "RaidHadBeUsed" : {"code" : 72034, "msg" : "该raid 被占用"},
    "dataInconsistentNumberOfItemsError" : {"code" : 72035, "msg" : "控制器Pci唯一号个数与控制器个数不一致！！！"},
    "CalcMaxArrayCapacityError" : {"code" : 72036, "msg" : "获取阵列最大可用容量失败"},
    "JoinGlobalSpareError" : {"code" : 72037, "msg" : "加入全局热备组失败"},
    "GetFreeRaidError" : {"code" : 72038, "msg" : "获取空闲raid失败"},
    "InitDiskListError" : {"code" : 72039, "msg" : "{detail}"},
    "HardRaidHaveUsedError" : {"code" : 72040, "msg" : "该硬raid已经用于存储池"},
    "GetSmartInfoError" : {"code" : 72041, "msg" : "获取磁盘smart信息失败"},
   

    # 73000 ~ 73499 为LVM模块错误码范围
    "FailedToFindPv" : {"code" : 73000, "msg" : "找不到物理卷"},
    "GetSinPvDetailError" : {"code" : 73001, "msg" : "获取物理卷详情失败"},
    "DeviceMayHaveData" : {"code" : 73002, "msg" : "该磁盘或分区可能存有数据"},
    "MountedFilesystem" : {"code" : 73003, "msg" : "该磁盘或分区已挂载文件系统"},
    "DeviceIsPvInVg" : {"code" : 73004, "msg" : "该磁盘或分区已是存储池中的物理卷"},
    "DeviceCannotBePv" : {"code" : 73005, "msg" : "该磁盘或分区不能添加为物理卷"},
    "AddPvError" : {"code" : 73006, "msg" : "添加物理卷失败"},
    "UseVgreduceFirst" : {"code" : 73007, "msg" : "请先将物理卷从存储池中移出"},
    "DeletePvError" : {"code" : 73008, "msg" : "删除物理卷失败"},
    "PvAlreadyInVg" : {"code" : 73009, "msg" : "该物理卷已存在于存储池"},
    "AddPvToVgError" : {"code" : 73010, "msg" : "加入存储池失败"},
    "PvInUse" : {"code" : 73011, "msg" : "该物理卷正在使用"},
    "FinalPvFromVg" : {"code" : 73012, "msg" : "存储池中的最后一个物理卷，需要删除存储池才能释放"},
    "PvNotInVG" : {"code" : 73013, "msg" : "该物理卷未加入任何存储池"},
    "ReducePvFromVgError" : {"code" : 73014, "msg" : "移出存储池失败"},

    "VgNotFound" : {"code" : 73015, "msg" : "找不到存储池"},
    "GetSinVgDetailError" : {"code" : 73016, "msg" : "获取存储池详情失败"},
    "VgAlreadyExists" : {"code" : 73017, "msg" : "存储池已存在"},
    "PvHasBeenUsed" : {"code" : 73018, "msg" : "物理卷已被使用"},
    "PvNotFound" : {"code" : 73019, "msg" : "找不到物理卷"},
    "AddVgError" : {"code" : 73020, "msg" : "添加存储池失败"},
    "VgContainLv" : {"code" : 73021, "msg" : "存储池中存在逻辑卷"},
    "DeleteVgError" : {"code" : 73022, "msg" : "删除存储池失败"},

    "FailedToFindLv" : {"code" : 73023, "msg" : "找不到逻辑卷"},
    "GetSinLvDetailError" : {"code" : 73024, "msg" : "获取逻辑卷详情失败"},
    "LvExistsInVg" : {"code" : 73025, "msg" : "逻辑卷已存在于存储池"},
    "VgNoFreeSpace" : {"code" : 73026, "msg" : "存储池可用空间不足"},
    "CreateLvError" : {"code" : 73027, "msg" : "添加逻辑卷失败"},
    "DeviceIsMounted" : {"code" : 73028, "msg" : "设备已挂载"},
    "DeviceIsInUse" : {"code" : 73029, "msg" : "设备正在被使用"},
    "SuperblockTooSmall" : {"code" : 73030, "msg" : "所要格式化的文件系统的超级块大小太小"},
    "FormatError" : {"code" : 73031, "msg" : "格式化失败"},
    "ExecuteSedCmdError": {"code": 73032, "msg": "执行替换指令失败"},
    "DirectoryNotExist" : {"code" : 73033, "msg" : "挂载目录不存在"},
    "AlreadyMounted" : {"code" : 73034, "msg" : "设备已挂载"},
    "FsTypeError" : {"code" : 73035, "msg" : "请先对设备进行格式化"},
    "UsedForDrbd" : {"code" : 73036, "msg" : "已用于卷复制，无法操作"},
    "DeviceNotExist" : {"code" : 73037, "msg" : "挂载设备不存在"},
    "MountError" : {"code" : 73038, "msg" : "挂载失败"},
    "NotMounted" : {"code" : 73039, "msg" : "设备未挂载"},
    "DeviceBusy" : {"code" : 73040, "msg" : "被其他设备使用中"},
    "UmountError" : {"code" : 73041, "msg" : "卸载失败"},
    "UmountLvFirst" : {"code" : 73042, "msg" : "请先卸载逻辑卷"},
    "LvIsUsedByOther" : {"code" : 73043, "msg" : "逻辑卷被其他设备使用中，无法操作"},
    "DeleteLvError" : {"code" : 73044, "msg" : "删除逻辑卷失败"},
    "CreateSnapError" : {"code" : 73045, "msg" : "创建快照失败"},
    "InvalidSnap" : {"code" : 73046, "msg" : "无效的快照，无法还原"},
    "RestoreSnapError" : {"code" : 73047, "msg" : "快照还原失败"},
	"CantUmountUsedLv" : {"code" : 73048, "msg" : "已创建共享存储，请先删除"},
    "CopySnapError" : {"code" : 73049, "msg" : "克隆快照失败"},    
    "CreateAutoSnapTaskError" : {"code" : 73050, "msg" : "创建自动快照任务失败"},
    "RemoveAutoSnapTaskError" : {"code" : 73051, "msg" : "删除自动快照任务失败"},
    "PauseAutoSnapTaskError" : {"code" : 73052, "msg" : "暂停自动快照任务失败"},
    "ResumeAutoSnapTaskError" : {"code" : 73053, "msg" : "恢复自动快照任务失败"},
    "ModifySnapTaskError" : {"code" : 73054, "msg" : "修改自动快照任务失败"},
    "SanLvCanNotFormat" : {"code" : 73055, "msg" : "SAN类型的卷禁止格式化操作"},
    "SetLvActiveFailed" : {"code" : 73056, "msg" : "启用逻辑卷失败"},
    "SetLvInactiveFailed" : {"code" : 73057, "msg" : "停用逻辑卷失败"},
    "LvIsMountedInUse" : {"code" : 73058, "msg" : "逻辑卷被挂载使用中，请先卸载"},
    "lvExtendCmdFailed" : {"code" : 73059, "msg" : "逻辑卷扩容失败"},   
    "PvIsExistsOnSystem" : {"code" : 73060, "msg" : "该物理卷已经存在于系统中"},
    "RemoveRunningAutoSnapError" : {"code" : 73061, "msg" : "任务正在运行中,禁止删除"},
    "InvalidAutoSnapTaskError" : {"code" : 73062, "msg" : "无效任务，不满足执行一次任务"},
    "AutoSnapTaskNameAlreadyExists" : {"code" : 73063, "msg" : "已经存在相同任务名称"},
    "LvInAutoSnapTask" : {"code" : 73064, "msg" : "逻辑卷已经创建有自动快照任务，请先删除任务"},


    # 73500 ~ 73999 为复制逻辑卷模块错误码范围
    "WipeLvDataError" : {"code" : 73500, "msg" : "擦除逻辑卷数据失败"},
    "CreateCopyLvResMdError" : {"code" : 73501, "msg" : "创建复制逻辑卷资源元数据失败"},
    "StartCopyLvResError" : {"code" : 73502, "msg" : "启用复制逻辑卷资源失败"},
    "SetCopyLvResRoleError" : {"code" : 73503, "msg" : "设置复制逻辑卷资源角色失败"},
    "AdjustCopyLvResError" : {"code" : 73504, "msg" : "调整复制逻辑卷资源失败"},
    "GetCopyLvCstateError" : {"code" : 73505, "msg" : "获取复制逻辑卷连接状态失败"},
    "CopyLvAlreadyMounted" : {"code" : 73506, "msg" : "复制逻辑卷已挂载，请先卸载"},
    "StopCopyLvResError" : {"code" : 73507, "msg" : "停用复制逻辑卷资源失败"},
    "CopyLvDisconnectError" : {"code" : 73508, "msg" : "复制逻辑卷资源断开连接失败"},
    "CopyLvConnectError" : {"code" : 73509, "msg" : "复制逻辑卷资源连接失败"},
    "CopyLvResAlreadyStarted" : {"code" : 73510, "msg" : "复制逻辑卷资源已启用，请先停用"},
    "WipeMdCopyLvResError" : {"code" : 73511, "msg" : "擦除复制逻辑卷资源元数据失败"},
    "DualMachineResIsEnabled" : {"code" : 73512, "msg" : "已启用的双机资源，禁止操作"},
    "CopyLvIsBusy" : {"code" : 73513, "msg" : "复制逻辑卷资源被占用，请先释放资源"},
    "CopyLvSecondaryCanotMount" : {"code" : 73514, "msg" : "复制逻辑卷从端角色无法挂载"},
    "ForceCopyLvToStandaloneFailed" : {"code" : 73515, "msg" : "强制复制逻辑卷进入脱机状态失败"},
    "LvFoundFilesystemCantCreateMd" : {"code" : 73516, "msg" : "逻辑卷已有文件系统，无法创建复制逻辑卷"},


    # 74000 ~ 74499 为SAN、NAS模块错误码范围
    "GetIscsiAllInfoError" : {"code" : 74000, "msg" : "获取iscsi信息出错"},
    "GetFreeResourceForIscsiError" : {"code" : 74001, "msg" : "给iscsi获取空闲资源信息出错"},
    "RunIscsiStringCmdError" : {"code" : 74002, "msg" : "iscsi 运行单行命令失败"},
    "iscsiDelTargetAccount" : {"code" : 74003, "msg" : "iscsi 删除账户失败"},
    "PathInexistence" : {"code" : 74004,"msg":"不存在的路经"},
    "IpOrNetError" : {"code": 74005,"msg":"ip地址格式错误"},
    "GetFileError" : {"code" : 74006,"msg":"获取配置文件出错"},
    "NameAlreadyExists" : {"code": 74007,"msg":"名称已存在"},
    "LvMustMounted" : {"code":74008,"msg":"逻辑盘需要先挂载才能使用"},    
    "ProhibitLocalIscsi" : {"code":74009,"msg":"禁止使用本机的iscsi设备"},
    "ThisIpNoneIscsi" : {"code":740010,"msg":"此ip没有iscsi设备"},
    "UserAlreadyExist" : {"code":740011,"msg":"该用户已存在在系统中"},
    "AddUserError" : {"code":740012,"msg":"添加用户失败"},
    "GetMountUserError" : {"code" : 74013,"msg":"获取挂载客户失败"},
    "GetNasUserError" : {"code" : 74014,"msg":"获取NAS客户失败"},
    "GetNasDirError" : {"code" : 74015,"msg":"获取NAS目录失败"},
    "DelNasUserError" : {"code" : 74016,"msg":"删除NAS客户失败"},
    "AddNasDirError" : {"code" : 74017,"msg":"添加NAS目录失败"},
    "DelNasDirError" : {"code" : 74018,"msg":"删除NAS目录失败"},
    "NasDirRecordNotExsits" : {"code" : 74019,"msg":"目录不存在"},
    "NasUserRecordNotExsits" : {"code" : 74020,"msg":"用户记录不存在"},
    "GroupNameAlreadyExists" : {"code": 74021,"msg":"组名已存在"},
    "CreateGroupFailed" : {"code": 74022,"msg":"创建用户组失败"},
    "DeleteGroupFailed" : {"code": 74023,"msg":"删除用户组失败"},
    "DeleteUserError" : {"code":740024,"msg":"删除用户错误"},
    "ModifyUserPasswdError" : {"code":740025,"msg":"用户密码设置错误：{errInfo}"},
    "OsUserAlreadyExist" : {"code":740026,"msg":"系统中不存在该用户"},
    "ExistsUsersInTheGroup" : {"code":7400276,"msg":"用户组存在用户，请先删除该用户组下所有用户"},
    "UserGroupNotExists" : {"code":740028,"msg":"用户组不存在"},
    "DirAlreadyExists" : {"code": 74029,"msg":"目录已存在"},
    "NfsUsedTheDir" : {"code": 74030,"msg":"NFS服务占用该目录，请先释放"},
    "SmbNfsUsedTheDir" : {"code": 74031,"msg":"CIFS服务占用该目录，请先释放"},
    "FtpUsedTheDir" : {"code": 74032,"msg":"FTP服务占用该目录，请先释放"},
    "CreateFtpShareError" : {"code": 74033,"msg":"创建ftp共享目录失败"},
    "NfsNameAlreadyExists" : {"code": 74034,"msg":"NFS共享目录已经存在"},
    "DeleteSambaUserError" : {"code": 74035,"msg":"CIFS用户删除失败"},
    "SambaNameAlreadyExists" : {"code": 74036,"msg":"CIFS共享目录已经存在"},
    "NasUserAlreadyUsedFtp" : {"code": 74037,"msg":"用户已经重复使用于FTP"},
    "UpdateSmUserPasswdError" : {"code": 74038,"msg":"更新CIFS用户密码失败"},
    "UpdateOsUserPasswdError" : {"code": 74039,"msg":"更新操作系统用户密码失败"},
    "DeleteSambaUserError" : {"code": 74040,"msg":"删除CIFS用户失败"},
    "DeleteFtpShareError" : {"code": 74041,"msg":"删除Ftp共享失败"},
    "FtpShareIsBusy": {"code": 74042,"msg":"Ftp共享正被使用"},
    "NasUserAlreadyUsedForSamba" : {"code": 74043,"msg":"用户已经使用于CIFS，请先删除对应CIFS共享"},
    "NasUserAlreadyUsedForFtp" : {"code": 74044,"msg":"用户已经使用于FTP，请先删除对应FTP共享"},
    "DoubleHaStatusError": {"code": 74045,"msg":"双机异常，无法操作"},
    "InvalidDirError":  {"code": 74046,"msg":"无效目录，无法操作"},
    "EditFtpShareError" : {"code": 74047,"msg":"修改ftp共享目录失败"},

    # 74500 ~ 74699 为SAN模块错误码范围
    "DelTargetAccountError" : {"code" : 74500, "msg" : "删除iscsi用户出错"},
    "AddNewTargetAccountError" : {"code" : 74501, "msg" : "添加新的iscsi target出错"},
    "DeleteTartgetCmdError" : {"code" : 74502, "msg" : "删除iscsi target出错"},
    "SetPermitHostAccessError" : {"code" : 74503, "msg" : "设置允许访问iscsi target 主机出错"},
    "DeleteTartgetLunCmdError" : {"code" : 74504, "msg" : "删除iscsi target lun 出错"},
    "AddTartgetLunCmdError" : {"code" : 74505, "msg" : "添加iscsi target lun 出错"},
    "AddTargetAccountCmdError" : {"code" : 74506, "msg" : "添加iscsi target 账户 出错"},
    "SetTargetActiveError" : {"code" : 74507, "msg" : "设置iscsi target 激活状态出错"},
    "GetIscsiAllAccountError" : {"code" : 74508, "msg" : "获取iscsi所有账户出错"},
    "AddAccountToIscsiError" : {"code" : 74509, "msg" : "添加iscsi账户出错"},
    "DelAccountToIscsiError" : {"code" : 74510, "msg" : "删除iscsi账户出错"},
    "IscsiServerNotOnline":  {"code": 74511, "msg":"ISCSI tgtd 服务不在线", "data":{}},
    "TargetHadExist":  {"code": 74512,"msg":"该target已经存在"},
    "CreateTargetFail":  {"code": 74513,"msg":"创建target失败"},
    "CurTargetHadLink":  {"code": 74514,"msg":'当前target正在被[{ipStr}]连接，请检查后再删除！！！'},
    "ParameterError":  {"code": 74515,"msg":'参数传递错误！！！'},
    "SetNoUserError":  {"code": 74516,"msg":'设置匿名访问失败'},
    "SetUserError":  {"code": 74517,"msg":'设置用户访问失败'},
    "TargetConfigFileNotExist":  {"code": 74518,"msg":"该target配置文件不存在"},
    "TargetInvalid":  {"code": 74519,"msg":"该 target 已经是无效状态"},
    "InvalidOperator":  {"code": 74520,"msg":"无效操作"},
    "AccountHadExist":  {"code": 74521,"msg":"该账户已经存在"},
    "GloableAccountHadUserdError":  {"code": 74522, "msg":"{detail}"},
    "CurTargetNotExist" : {"code": 74523,"msg":"{msg}"},


    # 74700 ~ 74999 为SAN模块: iscsi initiator 错误码范围
    "IpAdrressInfoError" : {"code": 74700,"msg":"ip地址格式错误"},
    "ConnectIscsiTargetFailed" : {"code": 74701,"msg":"连接iSCSI target失败"},
    "FailedToDeleteIscsi" : {"code": 74702,"msg":"删除iscsi失败"},
    "GetIscsiDetailError" : {"code": 74703,"msg":"获取iscsi详情失败"},
    "ThisDeviceWorksInVg" : {"code": 74704,"msg":"正在用于逻辑卷，无法删除"},
    "ThisDeviceWorksInRaid" : {"code": 74705,"msg":"正在用于RAID,无法删除"},    


    # 公共
    "MessageError": {"code": 88888, "msg": "报文错误，请修正重试"},
    "ServerServiceUnavaiable": {"code": 80002, "msg": "节点server服务连接失败"},
    "ServerServiceTimeout": {"code": 80003, "msg": "节点server服务连接超时"},
    "SystemError": {"code": 99999, "msg": "系统异常，请稍后重试"},
    "OtherError": {"code": -1, "msg": "未知异常"},
}


def get_error_result(error="Success", data=None, **kwargs):
    error_code = deepcopy(ERROR_CODE)
    error_msg = error_code.get(error, error_code.get("OtherError"))
    message = error_msg['msg'].format(**kwargs)
    if data is not None and isinstance(data, (dict, list, str)):
        error_msg.update({"data": data})
    error_msg['msg'] = F"{HOSTNAME}: {message}"
    return error_msg
