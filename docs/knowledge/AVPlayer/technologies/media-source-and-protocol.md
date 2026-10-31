# 媒体源与协议

> 媒体源类型、协议嗅探、下载调度、缓存分片、断点续传、路径安全。

## 一、媒体源类型

| 类型 | 方法 | 说明 | 缓存机制 |
|------|------|------|---------|
| URL | SetSource(url) | HTTP/HTTPS/File/FD 协议 | StreamCacheManager / DownloadedCacheManager |
| FD | SetSource(fd, offset, size) | 文件描述符 + 偏移范围 | 无 |
| DataSource | SetSource(dataSrc) | 自定义 IMediaDataSource 回调 | 无（加密场景） |
| AVMediaSource | SetMediaSource(source, strategy) | 媒体描述 + AVPlayStrategy | 依赖源类型 |

## 二、协议嗅探

### SourceParseAgent

| 方法 | 说明 |
|------|------|
| dlopen/dlsym | 动态加载协议 SO 库 |
| SniffStreamProtocol | 嗅探流协议类型 |
| GetSniffBufferSize | 获取嗅探所需最小字节数 |
| GetStreamResourceParser | 创建 StreamResourceParser 实例 |

### TypeFinder

| 方法 | 说明 |
|------|------|
| FindMediaType | 查找媒体类型 |
| SniffMediaType | 循环嗅探比较 confidence |
| GuessMediaType | 嗅探失败时根据 URI 后缀猜测 |

### HLS/DASH 解析流程

```
SourceParseAgent 动态加载协议 SO
  → GetSniffBufferSize() 确定嗅探字节数
  → SniffStreamProtocol() 识别 HLS/DASH
  → GetStreamResourceParser() 创建解析器
  → StreamResourceParser.Parse() 提取子资源列表
  → AVDownloaderManagerImpl 触发下载
  → 子资源缓存到本地
```

## 三、下载任务调度

### DownloaderImpl

| 特性 | 说明 |
|------|------|
| schedulerQueue_ | 任务调度队列 |
| schedulerThread_ | 专用调度线程 |
| DownloadTask | 单任务生命周期（Start/Pause/Resume/Cancel） |
| NetworkMonitor | 网络类型变化检测 |
| DownloadConfig | 进度回调间隔/超时/重试/网络偏好 |

### 多任务并发下载

- 管理多个 DownloadTask 实例
- 网络变化时调整下载策略
- 进度回调可配置频率

## 四、缓存分片策略

| 参数 | 值 | 说明 |
|------|-----|------|
| SHARD_SIZE | 4MB | 固定分片大小 |
| fragment index | offset / SHARD_SIZE | 分片索引计算 |

| 管理器 | 说明 |
|--------|------|
| StreamCacheManager | 内存中 URL → 分片集合索引 |
| DownloadedCacheManager | CacheMappingEntry 持久化分片索引 |

**特性**：支持随机访问无需下载整个文件、单分片完整性校验

## 五、断点续传

| 组件 | 说明 |
|------|------|
| DownloadedCacheManager | 构建 HTTP Range 请求头 |
| NetworkClient | Connect(offset) 支持偏移续传 |
| CacheMetaData | 存储 randomAccess 标志和已下载大小 |

## 六、路径安全验证

三层防御机制：

| 层 | 组件 | 说明 |
|----|------|------|
| 1 | PathValidator::Validate() | 核心路径校验 |
| 2 | DownloadedFileCacheManager::IsValidPath() | 缓存路径额外校验 |
| 3 | FileCacheManager | 操作前路径检查 |

- 防止路径遍历攻击
- 路径规范化处理

## 七、编解码器插件加载

- Histreamer 引擎动态加载编解码器插件
- AudioDecoderFilter / DecoderSurfaceFilter 通过插件接口加载具体实现
- 支持硬件和软件编解码插件
- DraggingPlayerAgent 使用 LoadLibrary/LoadSymbol 动态加载拖拽库
- DemuxerPlugin 也通过插件机制加载

## 知识关联

- [[architecture]] - 架构总览
- [[engine-layer-entities]] - 引擎层实体
- [[engine-factory-and-selection]] - 引擎工厂与选择