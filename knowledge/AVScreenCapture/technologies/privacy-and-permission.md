# 隐私保护与权限机制

> 录屏模块特有的隐私保护体系：权限校验、隐私窗口保护、授权弹窗、内容过滤、Picker 选择器。

## 一、权限体系

### 1.1 权限定义表

| 权限 | 用途 | 授权方式 |
|------|------|---------|
| `ohos.permission.CAPTURE_SCREEN` | 屏幕采集基础权限 | system_grant |
| `ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE` | 免授权录屏（系统级白名单） | system_grant |
| `ohos.permission.CUSTOM_SCREEN_RECORDING` | 自定义录屏（跳过弹窗） | system_grant |
| `ohos.permission.TIMEOUT_SCREENOFF_DISABLE_LOCK` | 录屏期间禁锁屏 | system_grant |

### 1.2 权限校验流程

```
CheckScreenCapturePermission()
  → AccessTokenKit::VerifyAccessToken(appTokenId, "ohos.permission.CAPTURE_SCREEN")
  → 返回 PERMISSION_GRANTED / PERMISSION_NOT_GRANTED
```

### 1.3 权限使用记录

录屏开始/停止时通过 PrivacyKit 记录权限使用：

```cpp
// 开始录屏
PrivacyKit::StartUsingPermission(appTokenId, "ohos.permission.CAPTURE_SCREEN", appPid)
PrivacyKit::AddPermissionUsedRecord(appTokenId, "ohos.permission.CAPTURE_SCREEN", 1, 0)

// 停止录屏
PrivacyKit::StopUsingPermission(appTokenId, "ohos.permission.CAPTURE_SCREEN", appPid)
```

**首实例/末实例机制**：只有同一 PID 的第一个启动实例记录 StartUsingPermission，最后一个停止实例记录 StopUsingPermission，避免多实例重复记录。

## 二、隐私窗口保护

### 2.1 PrivacyProtected 机制

```cpp
void PrivacyProtected(ScreenId &virtualScreenId, bool systemPrivacyProtectionSwitch,
                       bool appPrivacyProtectionSwitch);
```

通过两层保护控制虚拟屏幕可见性：

| 保护层 | API | 作用 |
|--------|-----|------|
| 系统隐私保护 | `SetScreenSkipProtectedWindow` | 跳过系统级隐私窗口（如密码输入、安全支付） |
| 应用隐私保护 | `SetScreenPrivacyWindowTagSwitch` | 跳过特定标签的隐私窗口 |

### 2.2 隐私窗口标签

| 标签 | 含义 | 保护层 |
|------|------|--------|
| `SCB_KEYBOARD_DEFAULT` | 系统键盘（软键盘弹窗） | 系统隐私保护 |
| `TAG_SCREEN_PROTECTION_SENSITIVE_APP` | 敏感应用窗口 | 应用隐私保护 |

当 systemPrivacy 和 appPrivacy 开关一致时，同时设置两个标签；不一致时分别设置。

### 2.3 OnPrivateWindowChange 回调

```
系统检测到隐私窗口出现/消失
  → PrivateWindowListenerWrapper::OnPrivateWindow(hasPrivate)
  → ScreenCaptureServer::OnPrivateWindowChange(hasPrivate)
  → cbProxy_->OnStateChange(ENTER_PRIVATE_SCENE / EXIT_PRIVATE_SCENE)
  → 应用层收到通知，可选择停止录屏或继续
```

### 2.4 OnPrivacyProtect 回调

```cpp
void NotifyprivacyProtect() {
    AVScreenCapturePrivacyProtect privacyProtect = {
        .appPrivacyProtection = appPrivacyProtectionSwitch_.load(),
        .systemPrivacyProtection = systemPrivacyProtectionSwitch_.load()
    };
    cbProxy_->OnPrivacyProtect(privacyProtect);
}
```

通知应用当前系统/应用隐私保护开关状态。

## 三、授权流程

### 3.1 授权判断链路

```
StartScreenCaptureInner
  ├── IsUserPrivacyAuthorityNeeded()
  │     ├── appUid == ROOT_UID(0) → false（Root 自动授权）
  │     └── 其它 → true（需要用户授权）
  │
  ├── CheckPrivacyWindowSkipPermission()
  │     └── AccessTokenKit::VerifyAccessToken(EXEMPT_CAPTURE_SCREEN_AUTHORIZE)
  │           → 有权限 → isScreenCaptureAuthority_ = true（免弹窗）
  │
  ├── IsSkipPrivacyWindow()
  │     ├── isSystemRecorder_ → true（系统录屏器跳过弹窗）
  │     └── CheckCustScrRecPermission() && !IsPickerPopUp() → true
  │           （自定义录屏权限 + Picker 未弹出 → 跳过弹窗）
  │
  └── RequestUserPrivacyAuthority(isSkipPrivacyWindow)
        ├── isSkipPrivacyWindow == true → 返回 MSERR_OK（跳过弹窗）
        ├── isPrivacyAuthorityEnabled_ == true → StartAuthWindow()
        │     → UIExtensionAbilityConnection 弹出授权弹窗
        │     → 用户 ALLOW → OnReceiveUserPrivacyAuthority(true)
        │     → 用户 DENY → OnReceiveUserPrivacyAuthority(false)
        └── isPrivacyAuthorityEnabled_ == false → CheckScreenCapturePermission()
```

### 3.2 StartAuthWindow

```
StartAuthWindow()
  ├── SUPPORT_SCREEN_CAPTURE_PICKER && IsPickerPopUp()
  │     → StartPicker()（弹出系统 Picker 选择器）
  └── 其它
        → BuildCommonParams(root)（构建 JSON 参数）
        → StartPrivacyWindow(JsonToString(root))
           → UIExtensionAbilityConnection::ConnectServiceExtensionAbility()
           → 弹出隐私授权弹窗
```

### 3.3 免授权场景

| 场景 | 判断条件 | 说明 |
|------|---------|------|
| Root 用户 | `appUid == ROOT_UID(0)` | 自动授权 |
| 系统录屏器 | `isSystemRecorder_ == true` | 跳过弹窗 |
| 免授权权限 | `EXEMPT_CAPTURE_SCREEN_AUTHORIZE` 权限 | 系统级白名单 |
| 自定义录屏 | `CUSTOM_SCREEN_RECORDING` 权限 + Picker 未弹出 | 跳过弹窗 |

### 3.4 OnReceiveUserPrivacyAuthority

```cpp
int32_t OnReceiveUserPrivacyAuthority(bool isAllowed) {
    if (!IsState(CAP_POPUP)) {
        // 状态非法 → OnError → StopScreenCaptureInner
        return MSERR_UNKNOWN;
    }
    if (!isAllowed) {
        captureState_ = CREATED;           // 回退到创建态
        cbProxy_->OnStateChange(CANCELED); // 通知取消
        return MSERR_UNKNOWN;
    }
    // 用户允许 → 继续启动
    int32_t ret = OnStartScreenCapture();
    PostStartScreenCapture(ret == MSERR_OK);
    return ret;
}
```

## 四、光标显示控制

通过 `SetVirtualScreenBlackList` 控制光标节点类型的可见性：

| showCursor | surfaceTypeList_ | 效果 |
|------------|------------------|------|
| true | 空 | 光标可见 |
| false | 光标节点类型 | 光标被黑名单过滤，不可见 |

## 五、白名单窗口

白名单与黑名单**可同时生效**，语义如下：

| 机制 | 含义 | 底层调用 |
|------|------|---------|
| 白名单 | 仅白名单内窗口可见，过滤白名单外的其它窗口 | `Rosen::ScreenManager::AddVirtualScreenWhiteList / RemoveVirtualScreenWhiteList` |
| 黑名单 | 黑名单内窗口不可见，其余窗口正常显示 | `Rosen::ScreenManager::SetVirtualScreenBlackList` |

| 方法 | 说明 |
|------|------|
| `AddWhiteListWindows(windowIDsVec)` | 添加窗口到白名单（仅这些窗口可见，过滤其余窗口） |
| `RemoveWhiteListWindows(windowIDsVec)` | 从白名单移除窗口（恢复该窗口的默认可见性） |

## 六、内容过滤

```cpp
struct ScreenCaptureContentFilter {
    std::set<AVScreenCaptureFilterableAudioContent> filteredAudioContents;
    std::vector<uint64_t> windowIDsVec;
};
```

| 过滤类型 | 枚举 | 说明 |
|----------|------|------|
| 通知音 | `SCREEN_CAPTURE_NOTIFICATION_AUDIO` | 过滤系统通知声音 |
| 当前应用音 | `SCREEN_CAPTURE_CURRENT_APP_AUDIO` | 过滤录屏应用自身音频 |
| 窗口黑名单 | `windowIDsVec` | 指定窗口在录屏中不可见 |

`ExcludeContent` 同时更新视频黑名单（`SetVirtualScreenBlackList`）和音频过滤（`UpdateAudioCapturerConfig`）。

## 七、内容变更通知

```cpp
enum AVScreenCaptureContentChangedEvent {
    SCREEN_CAPTURE_CONTENT_HIDE = 0,        // 内容隐藏
    SCREEN_CAPTURE_CONTENT_VISIBLE = 1,     // 内容可见
    SCREEN_CAPTURE_CONTENT_UNAVAILABLE = 2, // 内容不可用
};
```

| 事件 | 触发场景 |
|------|---------|
| HIDE | 录制窗口进入后台、窗口移出采集屏幕 |
| VISIBLE | 录制窗口回到前台、窗口移入采集屏幕 |
| UNAVAILABLE | 录制窗口被销毁、采集屏幕断开 |

通过 `OnCaptureContentChanged` 回调通知应用，携带 `ScreenCaptureRect` 区域信息。

## 八、Picker 选择器

### 8.1 Picker 弹出

```cpp
int32_t PresentPicker();  // 弹出系统 Picker
```

仅 `SUPPORT_SCREEN_CAPTURE_PICKER` 宏启用时可用，需在 `CAP_RUNNING` 状态调用。

### 8.2 Picker 模式

```cpp
enum class PickerMode {
    WINDOW_ONLY = 0,      // 仅窗口
    SCREEN_ONLY = 1,      // 仅屏幕
    SCREEN_AND_WINDOW = 2,// 屏幕和窗口
    APP_ONLY = 3,         // 仅应用
    WINDOW_AND_APP = 4,   // 窗口和应用
    SCREEN_AND_APP = 5,   // 屏幕和应用
    SCREEN_WINDOW_AND_APP = 6, // 全部
};
```

### 8.3 条件编译

| 宏 | 平台 | Picker 行为 |
|----|------|------------|
| `SUPPORT_SCREEN_CAPTURE_PICKER` | 全局 | Picker 功能总开关 |
| `PC_STANDARD` | PC | `SendConfigToUIParams` 通过 Want 传参 |
| `SUPPORT_PICKER_PHONE_PAD` | 手机/平板 | `BuildPickerParams` 通过 JSON 传参 |

### 8.4 Picker 用户选择流程

```
PresentPicker → isPresentPickerPopWindow_ = true
  → 用户在 Picker 中选择窗口/屏幕/应用
  → ReportAVScreenCaptureUserChoice(content) → JSON 解析
  → HandlePresentPickerWindowCase：
    - DestroyVirtualScreen()（销毁旧虚拟屏幕）
    - SetCaptureConfig(captureMode, missionId)（更新采集配置）
    - OnReceiveUserPrivacyAuthority(true)（继续启动）
```

## 九、通话期间保持录屏

条件编译 `SUPPORT_CALL`：

```cpp
#ifdef SUPPORT_CALL
void OnCallStateChanged(bool isInCall) {
    if (!captureConfig_.strategy.keepCaptureDuringCall && isInCall) {
        StopScreenCaptureByEvent(STOPPED_BY_CALL);
        Release();
        return;
    }
    isInTelCall_.store(isInCall);
    SyncAudioCaptures();  // 通话期间停止麦克风采集
}
#endif
```

| 策略 | keepCaptureDuringCall | 通话时行为 |
|------|----------------------|-----------|
| 默认 | false | 停止录屏，释放实例 |
| 保持 | true | 继续录屏，停止麦克风 |

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期（授权流程集成）
- [[ipc-communication]] - IPC 通信与回调机制
- [[capture-features]] - 录制控制特性
- [[design-patterns]] - 设计模式（Wrapper 模式管理监听器）
- [[flows]] - 关键流程详解（授权弹窗流程、Picker 流程）
