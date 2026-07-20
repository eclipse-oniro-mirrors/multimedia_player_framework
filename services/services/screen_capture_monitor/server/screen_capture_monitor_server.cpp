/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "screen_capture_monitor_server.h"
#include "map"
#include "media_log.h"
#include "media_errors.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "media_dfx.h"
#include "hitrace/tracechain.h"
#include "media_utils.h"
#include "screen_capture_server.h"
#include "tokenid_kit.h"
#include "access_token.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureMonitorServer"};
}

namespace OHOS {
namespace Media {
ScreenCaptureMonitorServer &ScreenCaptureMonitorServer::GetInstance()
{
    static ScreenCaptureMonitorServer instance;
    return instance;
}

ScreenCaptureMonitorServer::ScreenCaptureMonitorServer()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

ScreenCaptureMonitorServer::~ScreenCaptureMonitorServer()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    Release();
}

int32_t ScreenCaptureMonitorServer::Release()
{
    MEDIA_LOGI("ScreenCaptureMonitorServer:0x%{public}06" PRIXPTR " Release S", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    screenCaptureMonitorCbSet_.clear();
    return MSERR_OK;
}

std::list<int32_t> ScreenCaptureMonitorServer::IsScreenCaptureWorking()
{
    MEDIA_LOGI("ScreenCaptureMonitorServer:0x%{public}06" PRIXPTR " IsScreenCaptureWorking S", FAKE_POINTER(this));
    std::list<int32_t> pidList{};
    OHOS::Media::ScreenCaptureServer::GetRunningScreenCaptureInstancePid(pidList);
    for (auto pid : pidList) {
        MEDIA_LOGD("ScreenCaptureMonitorServer::IsScreenCaptureWorking pid %{public}d", pid);
    }
    return pidList;
}

void ScreenCaptureMonitorServer::SetScreenCaptureMonitorCallback(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> callback)
{
    MediaTrace trace("ScreenCaptureMonitorServer::SetScreenCaptureCallback");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(callback != nullptr, "SetScreenCaptureCallback failed, callback is nullptr");
    screenCaptureMonitorCbSet_.insert(callback);
    MEDIA_LOGI("ScreenCaptureMonitorServer: 0x%{public}06" PRIXPTR "SetScreenCaptureCallback OK.", FAKE_POINTER(this));
}

void ScreenCaptureMonitorServer::RemoveScreenCaptureMonitorCallback(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> callback)
{
    MediaTrace trace("ScreenCaptureMonitorServer::RemoveScreenCaptureMonitorCallback");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(callback != nullptr, "RemoveScreenCaptureMonitorCallback failed, callback is nullptr");
    screenCaptureMonitorCbSet_.erase(callback);
    MEDIA_LOGI("ScreenCaptureMonitorServer: 0x%{public}06" PRIXPTR "RemoveScreenCaptureMonitorCallback OK.",
        FAKE_POINTER(this));
}

void ScreenCaptureMonitorServer::RegisterScreenCaptureMonitorListener(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> callback)
{
    MEDIA_LOGI("ScreenCaptureMonitorServer:0x%{public}06" PRIXPTR " RegisterScreenCaptureMonitorListener",
        FAKE_POINTER(this));
}

void ScreenCaptureMonitorServer::UnregisterScreenCaptureMonitorListener(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> listener)
{
    MEDIA_LOGI("ScreenCaptureMonitorServer:0x%{public}06" PRIXPTR " UnregisterScreenCaptureMonitorListener",
        FAKE_POINTER(this));
}

int32_t ScreenCaptureMonitorServer::CallOnScreenCaptureStarted(int32_t pid)
{
    MEDIA_LOGI("ScreenCaptureMonitorServer::CallOnScreenCaptureStarted S");
    std::set<sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener>> cbSet;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cbSet = screenCaptureMonitorCbSet_;
    }
    for (const auto &value : cbSet) {
        if (value != nullptr) {
            value->OnScreenCaptureStarted(pid);
        }
    }
    return MSERR_OK;
}

int32_t ScreenCaptureMonitorServer::CallOnScreenCaptureFinished(int32_t pid)
{
    MEDIA_LOGI("ScreenCaptureMonitorServer::CallOnScreenCaptureFinished S");
    std::set<sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener>> cbSet;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cbSet = screenCaptureMonitorCbSet_;
    }
    for (const auto &value : cbSet) {
        if (value != nullptr) {
            value->OnScreenCaptureFinished(pid);
        }
    }
    return MSERR_OK;
}

void ScreenCaptureMonitorServer::SetSystemScreenRecorderStatus(bool started)
{
    MEDIA_LOGI("ScreenCaptureMonitorServer::SetSystemScreenRecorderStatus S, state: %{public}d", started);
    std::lock_guard<std::mutex> lock(mutex_);
    isSystemScreenRecorderWorking_ = started;
}

bool ScreenCaptureMonitorServer::IsSystemScreenRecorder(int32_t pid)
{
    MEDIA_LOGI("ScreenCaptureMonitorServer::IsSystemScreenRecorder S");
    if (pid < 0) {
        MEDIA_LOGW("ScreenCaptureMonitorServer::IsSystemScreenRecorder invalid pid: %{public}d", pid);
        return false;
    }
    bool result = ScreenCaptureServer::CheckPidIsScreenRecorder(pid);
    MEDIA_LOGI("ScreenCaptureMonitorServer::IsSystemScreenRecorder result: %{public}d", result);
    return result;
}

bool ScreenCaptureMonitorServer::IsSystemScreenRecorderWorking()
{
    MEDIA_LOGI("ScreenCaptureMonitorServer::IsSystemScreenRecorderWorking S");
    std::lock_guard<std::mutex> lock(mutex_);
    return isSystemScreenRecorderWorking_;
}

bool ScreenCaptureMonitorServer::IsSystemApp()
{
    uint64_t accessTokenIDEx = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx);
    return isSystemApp;
}

bool ScreenCaptureMonitorServer::HasSystemPermission()
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType == Security::AccessToken::TOKEN_NATIVE || tokenType == Security::AccessToken::TOKEN_SHELL) {
        return true;
    }
    return IsSystemApp();
}
} // namespace Media
} // namespace OHOS
