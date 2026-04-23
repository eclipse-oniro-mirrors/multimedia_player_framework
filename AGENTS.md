# AGENTS.md - Coding Agent Guidelines for multimedia_player_framework

## 简介 / Introduction

本仓库是OpenHarmony媒体组件（multimedia_player_framework），提供音视频播放、录制、转码、录屏等媒体服务的API实现。代码主要使用C++，采用GN（Generate Ninja）构建系统。

This is the OpenHarmony multimedia player framework repository. It provides APIs for audio/video playback, recording, transcoding, screen capture, and related media services. The codebase is primarily C++ using the GN build system.

## 目录结构 / Directory Structure

```
/foundation/multimedia/player_framework
├── interfaces                           # 外部接口层 / Interface layer
│   ├── kits                             # 应用接口 / Application interface (JS/NAPI, C API)
│   └── inner_api                        # 系统内部件接口 / Internal APIs
├── frameworks                           # 部件无独立进程的实现 / Client implementation
│   ├── js                               # JS NAPI实现 / JS NAPI bindings
│   ├── native                           # Native C++实现 / Native C++ implementation
│   ├── taihe                            # Taihe框架实现 / Taihe framework
│   └── cj                               # CJ语言绑定 / CJ language bindings
├── services                             # 服务C/S实现 / Service implementation
│   ├── services                         # 服务框架 / Service framework (player, recorder, etc.)
│   ├── engine                           # 引擎实现 / Engine implementation
│   │   └── histreamer                   # HiStreamer引擎 / HiStreamer engine
│   ├── utils                            # 子系统基础资源 / Common utilities
│   ├── dfx                              # DFX诊断功能 / DFX diagnostics
├── test                                 # 测试代码 / Test code
│   ├── unittest                         # 单元测试 / Unit tests
│   ├── fuzztest                         # 模糊测试 / Fuzz tests
│   └── example                          # 示例代码 / Example code
├── config.gni                           # 构建配置和特性开关 / Build config and feature flags
├── BUILD.gn                             # 编译入口 / Build entry
└── bundle.json                          # 部件描述文件 / Component description
```

## 构建命令 / Build Commands

### 全量构建 / Full Build
```bash
# 构建完整媒体包 / Build full media packages
./build.sh --product-name <product_name> --build-target media_packages

# 构建服务组 / Build service group
./build.sh --product-name <product_name> --build-target media_services_package

# 构建框架组（客户端库）/ Build framework group (client libraries)
./build.sh --product-name <product_name> --build-target napi_packages
./build.sh --product-name <product_name> --build-target capi_packages
```

## 测试命令 / Test Commands

### 运行所有单元测试 / Run All Unit Tests
```bash
./build.sh --product-name <product_name> --build-target media_unit_test
```

### 运行单个单元测试 / Run a Single Unit Test
测试定义在`test/unittest/*/BUILD.gn`中。运行指定测试：
```bash
# 构建指定测试目标 / Build specific test target
./build.sh --product-name <product_name> --build-target hiplayer_impl_unit_test

# 构建完成后运行测试二进制 / Run test binary after build
# 测试二进制通常位于 out/<product>/tests/unittest/player_framework/
```

### 运行模糊测试 / Run Fuzz Tests
```bash
./build.sh --product-name <product_name> --build-target media_fuzz_test
```

### 主要测试目标 / Key Test Targets (from test/BUILD.gn)
- `hiplayer_impl_unit_test` - 播放器实现测试 / Player implementation tests
- `player_server_unit_test` - 播放器服务端测试 / Player server tests
- `avmetadatahelper_unit_test` - 元数据助手测试 / Metadata helper tests
- `soundpool_unit_test` - SoundPool测试 / SoundPool tests
- `screen_capture_unit_test` - 录屏测试 / Screen capture tests
- `recorder_unit_test` - 录制器测试 / Recorder tests
- `transcoder_unit_test` - 转码器测试 / Transcoder tests

## 代码风格指南 / Code Style Guidelines

### 文件头 / File Headers
所有源文件必须包含Apache License 2.0头：
```cpp
/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
```

### 头文件保护符 / Header Guards
使用`#ifndef`风格，匹配文件路径：
```cpp
#ifndef HI_PLAYER_IMPL_H
#define HI_PLAYER_IMPL_H
...
#endif  // HI_PLAYER_IMPL_H
```

### 命名空间 / Namespaces
使用嵌套命名空间模式，带结尾注释：
```cpp
namespace OHOS {
namespace Media {
// code here
}  // namespace Media
}  // namespace OHOS
```

匿名命名空间用于局部常量/辅助函数：
```cpp
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "HiPlayer" };
}
```

### 命名规范 / Naming Conventions

| 类型/Type | 规范/Convention | 示例/Example |
|-----------|-----------------|--------------|
| 类/Classes | PascalCase | `HiPlayerImpl`, `PlayerServer` |
| 函数/方法/Functions | PascalCase | `SetSource`, `GetDuration` |
| 成员变量/Member Variables | camelCase带尾部下划线 | `hiplayer_`, `currState_` |
| 局部变量/Local Variables | camelCase | `ret`, `bundleName` |
| 常量/Constants | UPPER_CASE或constexpr | `MAX_MEDIA_VOLUME`, `PLAY_RANGE_DEFAULT_VALUE` |
| 枚举/Enums | PascalCase名称, UPPER_CASE值 | `PlayerStateId::PLAYING` |
| 宏/Macros | UPPER_CASE带下划线 | `CHECK_AND_RETURN`, `MEDIA_LOGE` |

### Include顺序 / Include Order
1. 相关头文件（如`"hiplayer_impl.h"`对应hiplayer_impl.cpp）
2. 系统/C标准头文件（如`<cstdint>`, `<string>`）
3. 第三方头文件
4. 项目头文件，按字母顺序

```cpp
#include "hiplayer_impl.h"

#include <chrono>
#include <shared_mutex>

#include "common/log.h"
#include "media_errors.h"
#include "media_utils.h"
```

### 日志 / Logging
使用`services/utils/include/media_log.h`中的日志宏：
```cpp
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "ComponentName" };

MEDIA_LOG_I("Component initialized");
MEDIA_LOG_E("Failed to open file: %{public}s", filename.c_str());
MEDIA_LOG_D("Debug info: %{public}d", value);
MEDIA_LOG_W("Warning message");
```

### 错误处理 / Error Handling
使用`media_log.h`中的CHECK宏进行验证：
```cpp
CHECK_AND_RETURN(ptr != nullptr);                          // 失败返回void
CHECK_AND_RETURN_RET(ptr != nullptr, MSERR_INVALID_VAL);   // 失败返回值
CHECK_AND_RETURN_RET_LOG(status != Status::ERROR, MSERR_UNKNOWN, "Error: %{public}d", status);
CHECK_AND_BREAK_LOG(condition, "Check failed");            // 循环中break
CHECK_AND_CONTINUE(condition);                             // 循环中continue
```

错误码定义为`MSERR_*`常量（如`MSERR_OK`, `MSERR_INVALID_VAL`, `MSERR_UNKNOWN`）。

### 类与继承 / Classes and Inheritance
```cpp
class PlayerServer
    : public IPlayerService,
      public IPlayerEngineObs,
      public NoCopyable,
      public PlayerServerStateMachine {
public:
    static std::shared_ptr<IPlayerService> Create();
    PlayerServer();
    virtual ~PlayerServer();
    DISALLOW_COPY_AND_MOVE(PlayerServer);
    int32_t Play() override;
    int32_t Pause() override;
};
```

### 函数可见性 / Function Visibility
导出公共函数使用visibility属性：
```cpp
std::string __attribute__((visibility("default"))) GetClientBundleName(int32_t uid);
```

### 测试代码风格（GTest）/ Test Code Style
```cpp
namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

class HiplayerImplUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    std::unique_ptr<HiPlayerImpl> hiplayer_;
};

/**
 * @tc.name    : Test GetRealPath API
 * @tc.number  : GetRealPath_001
 * @tc.desc    : Test GetRealPath interface
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(HiplayerImplUnitTest, GetRealPath_001, TestSize.Level0)
{
    std::string url = "file://";
    std::string realUrlPath;
    int32_t ret = hiplayer_->GetRealPath(url, realUrlPath);
    EXPECT_EQ(ret, MSERR_OPEN_FILE_FAILED);
}
}  // namespace Media
}  // namespace OHOS
```

### 格式化 / Formatting
- 缩进：4空格，无Tab
- 最大行长度：100-120字符
- 大括号：控制语句同行
- 指针/引用：类型相邻（`std::string& name`, `int32_t* ptr`）

### GN构建文件风格 / GN Build File Style
```python
import("//build/test.gni")
import("//foundation/multimedia/player_framework/config.gni")

module_output_path = "player_framework/player_framework/player"

config("module_config") {
  visibility = [ ":*" ]
  cflags = [ "-O2", "-fPIC", "-Wall", "-fexceptions" ]
  include_dirs = [ ... ]
}

ohos_unittest("test_name") {
  module_out_path = module_output_path
  sources = [ "test_file.cpp" ]
  configs = [ ":module_config" ]
  external_deps = [ "hilog:libhilog", "c_utils:utils" ]
  deps = [ ... ]
}
```

## 重要路径参考 / Key Paths Reference

| 路径/Path | 用途/Purpose |
|-----------|--------------|
| `interfaces/inner_api/native/` | 公共API头文件 / Public API headers |
| `interfaces/kits/js/` | JavaScript/NAPI绑定 / JS bindings |
| `interfaces/kits/c/` | C API绑定 / C API bindings |
| `frameworks/native/` | 客户端实现 / Client implementation |
| `services/services/` | 服务实现（服务端）/ Service implementation |
| `services/engine/histreamer/` | 播放器引擎实现 / Player engine |
| `services/utils/include/` | 公共工具 / Common utilities |
| `test/unittest/` | 单元测试 / Unit tests |
| `test/fuzztest/` | 模糊测试 / Fuzz tests |
| `config.gni` | 构建配置和特性开关 / Build config |

## 重要说明 / Important Notes

- 项目使用`config.gni`进行特性开关配置，检查`player_framework_support_*`变量进行条件编译
- 使用`MSERR_OK`(0)表示成功，负值表示错误
- 始终使用`CHECK_AND_RETURN*`宏而非原始if-return进行验证
- 添加新代码时遵循类似文件中的现有模式
- 测试Mock类应放在测试文件夹的`mock/`子目录中