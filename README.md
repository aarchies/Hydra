# 项目结构

```shell
├── build/
│   ├── plugs/                # wireshark 插件
│   └── suricata-7.0.5.tar.gz # suricata 源码安装包
├── include/
│   ├── lib/unix/             # 动态库文件
│   ├── lib/win/              # 动态库文件
│   ├── libparser.h           # Go 导出的头文件
│   └── tshark.h              # tshark 头文件
├── internal/
│   ├── core/                 # 核心逻辑
│   └── plugin/               # 插件系统
│       ├── session/          # 会话管理插件
│       │   ├── handler.go    # 会话处理
│       │   ├── config.go     # 会话配置
│       │   └── pb/           # Protobuf 定义
│       │
│       ├── store/            # 存储插件
│       │   ├── handler.go    # 存储处理
│       │   └── config.go     # 存储配置
│       │
│       ├── warn/             # 告警插件
│       │   ├── handler.go    # 告警处理
│       │   └── config.go     # 告警配置
│       │
│       └── offline/          # 离线分析插件
│           ├── handler.go    # 离线处理
│           └── config.go     # 离线配置
├── export/                   # 导出函数
│   ├── func.go               # C 导出函数
│   ├── packet.go             # 数据包处理
│   └── socket.go             # Socket 服务
└── main.go                   # 入口文件
```

## 开发须知

1. 新增插件需要注册插件 根目录下plugin.cfg,可参考现有插件注册方式
2. include cgo头文件，分别在win/unix 加载lib目录中的dll或者so文件

## 流量链路

```shell
1. 初始化流程:
main.go -> init()
  ├── config.MustLoad()           # 加载配置
  ├── module.Register()           # 注册模块
  └── core.Run()                  # 启动核心
      ├── tshark.Init()           # 初始化 tshark
      └── instance.Register()     # 注册实例
          └── Entrance()          # 入口函数

2. 数据处理流程:

1. Socket 模式:
   socket.StartSocketServer() -> Entrance() -> analyzer()

2. 导出函数模式:
   Entrance() -> analyzer() -> dissect_single_packet()

3. 离线分析模式:
   offline.ProcessPcap() -> suricata.Send() -> analyzer()

3. 插件处理流程:
analyzer()
  ├── dissect_single_packet()     # Tshark 解析
  ├── convertGoPacketResult()     # 结果转换
  └── processPacketResult()       # 结果处理
      └── plugin.Handle()         # 插件处理

4. 函数调用链路:
 app.init()
      -> module.Register()
          -> plugin.Register()
               -> plugin.Init()
                     -> core.Run()
                           ├── tshark.Init()          # Tshark 初始化
                           └── instance.Register()     # 注册处理实例
                                 ├── socket.StartSocketServer()   # Socket 服务 if win
                                 └── analyzer()                   # 核心分析
                                      ├── dissect_single_packet() # 数据包解析
                                      ├── convertGoPacketResult() # 结果转换
                                      └── processPacketResult()   # 结果处理
                                           └── plugin.Handle()    # 插件处理

5. 数据流转过程:

1. 数据输入
   ├── Socket 接收
   ├── 导出函数调用
   └── 离线文件分析

2. 数据处理
   ├── Tshark 解析
   ├── 结果转换
   └── 插件处理
       ├── 会话管理
       ├── 数据存储
       ├── 告警处理
       └── 离线分析
```
 
# 架构设计

1. mpg并发模型
```shell

```

2.父子进程通信
```shell
 (1).go->runtime->actor
 本质上类似于channal的实现，底层为ringbuffer 
 (2).父/子各进行双向mmap映射绑定+futex同步原语

```

2. 权重调度

``` shell
                      +----------------+
                      | 流量入口网关   |
                      +--------+-------+
                               | 哈希分发
                      +--------v-------+
                      | 父进程调度中心 | 
                      +--------+-------+
                               | 权重动态分配
       +-----------------------+-----------------------+
       |                       |                       |
+------v------+         +------v------+         +------v------+
| 子进程1     |         | 子进程2     |         | 子进程N     |
| (权重动态) |         | (权重动态) |         | (权重动态) |
+------------+         +------------+         +------------+
```

2. 三维权重计算

``` shell
// 父进程公式
0.4*(CPU因子) + 0.3*(Pending因子) + 0.3*(内存因子)

// 子进程公式 
0.5*(CPU因子) + 0.2*(Pending因子) + 0.3*(内存因子)
```

3. 资源动态及自愈机制

```shell
graph TD
    A[Controller] -->|监控| B(Metrics Collector)
    A -->|调度| C[M Pool]
    A -->|管理| D[P Pool]
    C --> E[M1]
    C --> F[M2]
    E --> G[P1]
    E --> H[P2]
    F --> I[P3]
    B -->|收集| J[CPU/Mem/Pending]

graph TD
    A[开始检查] --> B{CPU>70%或任务堆积?}
    B -->|是| C[执行扩容]
    B -->|否| D{CPU<30%且空闲?}
    D -->|是| E[执行缩容]
    D -->|否| F[保持现状]

sequenceDiagram
    participant H as 健康检查
    participant C as Controller
    participant M as 故障M
    
    H->>C: 发现M无响应
    C->>M: 标记为故障状态
    C->>C: 转移任务到其他M
    C->>M: 发送重启指令
    M->>M: 清理旧上下文
    M->>M: 创建新上下文
    M->>M: 重启运行循环
    M->>C: 重新注册到备用池

stateDiagram-v2
    [*] --> Active: 正常启动
    Active --> Faulty: 检测到故障
    Faulty --> Recovering: 开始恢复
    Recovering --> Standby: 恢复完成
    Standby --> Active: 被重新激活
    Recovering --> Faulty: 恢复失败            
```