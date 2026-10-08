<p align="center"><img src="assets/rdpsafe.png" width="96" /></p>

<h1 align="center">RDPSafe</h1>
<p align="center">Windows 远程桌面（RDP）防暴力破解工具</p>

RDPSafe 实时监控 Windows 登录事件，自动识别针对远程桌面的暴力破解，并通过 Windows 防火墙封禁攻击来源 IP。防护引擎以系统服务运行，开机即生效、无需登录；管理界面提供态势概览、登录记录、封禁管理、黑白名单与防火墙规则管理。

## 功能

- **实时检测**：订阅安全日志 4625 / 4624 事件，并关联 RdpCoreTS 140 事件，补齐开启 NLA 时缺失的来源 IP
- **自动封禁**：N 分钟内失败 M 次即封禁；支持敏感用户名一次即封、自动解封、递增封禁、封禁时断开现有连接
- **聚合防火墙规则**：所有封禁 IP 分组写入少量规则（每条最多 1000 个地址），封禁上万 IP 也不会拖慢防火墙；每 10 分钟自动对账
- **防误封**：白名单（支持 CIDR）、不封禁存在活动远程会话的 IP、登录成功自动加入白名单（可选）
- **黑名单**：手动永久封禁 IP 或网段
- **防火墙规则管理**：查看、新建、编辑、启用/禁用、删除入站规则
- **离线 IP 归属地**：内置 [ip2region](https://github.com/lionsoul2014/ip2region) 数据库
- **自检**：自动开启“审核登录”策略；Windows 防火墙关闭时醒目提示并可一键开启（会先放行远程桌面端口）
- **单文件**：一个 `RDPSafe.exe`，自带 .NET 运行时，无需安装任何依赖

## 使用

1. 将 `RDPSafe.exe` 放到固定目录，例如 `C:\Program Files\RDPSafe\`（服务会记住该路径）
2. 运行 `RDPSafe.exe`（需要管理员权限），按提示安装并启动防护服务
3. 若通过远程桌面操作，程序会自动把你当前的来源 IP 加入白名单

命令行：

```
RDPSafe.exe                 打开管理界面
RDPSafe.exe --install       安装并启动防护服务
RDPSafe.exe --uninstall     卸载防护服务（保留数据与封禁规则）
RDPSafe.exe --uninstall-all 完全卸载：服务、防火墙规则、计划任务、数据目录
RDPSafe.exe --remove-rules  删除全部 RDPSafe 防火墙规则
RDPSafe.exe --version       显示版本号
```

数据保存在 `C:\ProgramData\RDPSafe\`（仅 SYSTEM 与管理员可访问）。

系统要求：Windows 10 / 11 / Server 2016 及以上（x64）。

## 构建

需要 [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)。

```
build.cmd
```

输出 `publish\RDPSafe.exe` 与 `publish\RDPSafe-<版本号>-win-x64.zip`。版本号在 `Directory.Build.props` 中统一维护。

## 项目结构

```
src/RDPSafe.Core    核心库：事件采集与关联、检测、封禁、防火墙、数据存储、IPC
src/RDPSafe.App     WPF 管理界面；带 --service 参数时作为 Windows 服务运行引擎
tools/              开发辅助工具（图标生成、核心功能测试、界面截图）
data/               ip2region 离线 IP 库（编译时内嵌）
```

## 架构

```
RDPSafe.exe --service (Windows 服务, LocalSystem)
  事件采集 ─► 4625/140 关联去重 ─► 入库 ─► 滑动窗口检测 ─► 封禁 ─► 聚合防火墙规则
  定时任务：到期解封 / 日志清理 / 防火墙对账 / 审核策略与防火墙状态检查
  命名管道（仅管理员可连接）◄──── RDPSafe.exe（管理界面）
                                    服务未运行时界面直接执行操作
```

## 致谢

- IP 归属地数据：[lionsoul2014/ip2region](https://github.com/lionsoul2014/ip2region)（Apache-2.0）
