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
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "hitrace/tracechain.h"
#include "media_utils.h"

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
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Release S", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    screenCaptureMonitorCbSet_.clear();
    return MSERR_OK;
}

std::list<int32_t> ScreenCaptureMonitorServer::IsScreenCaptureWorking()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " IsScreenCaptureWorking S", FAKE_POINTER(this));
    std::list<int32_t> pidList;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto &entry : runningCapturePidCounts_) {
            pidList.push_back(entry.first);
        }
    }
    for (auto pid : pidList) {
        MEDIA_LOGD("IsScreenCaptureWorking pid %{public}d", pid);
    }
    return pidList;
}

void ScreenCaptureMonitorServer::AddRunningCapturePid(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    runningCapturePidCounts_[pid]++;
    MEDIA_LOGI("AddRunningCapturePid %{public}d, count=%{public}d", pid, runningCapturePidCounts_[pid]);
}

void ScreenCaptureMonitorServer::RemoveRunningCapturePid(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = runningCapturePidCounts_.find(pid);
    if (it != runningCapturePidCounts_.end()) {
        it->second--;
        if (it->second <= 0) {
            runningCapturePidCounts_.erase(it);
        }
    }
    MEDIA_LOGI("RemoveRunningCapturePid %{public}d, remaining=%{public}d", pid,
        runningCapturePidCounts_.count(pid) > 0 ? runningCapturePidCounts_[pid] : 0);
}

int32_t ScreenCaptureMonitorServer::GetRunningCapturePidCount(int32_t pid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = runningCapturePidCounts_.find(pid);
    if (it == runningCapturePidCounts_.end()) {
        return 0;
    }
    return it->second;
}

void ScreenCaptureMonitorServer::SetScreenCaptureMonitorCallback(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> callback)
{
    MediaTrace trace("SetScreenCaptureCallback");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(callback != nullptr, "SetScreenCaptureCallback failed, callback is nullptr");
    screenCaptureMonitorCbSet_.insert(callback);
    MEDIA_LOGI("0x%{public}06" PRIXPTR "SetScreenCaptureCallback OK.", FAKE_POINTER(this));
}

void ScreenCaptureMonitorServer::RemoveScreenCaptureMonitorCallback(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> callback)
{
    MediaTrace trace("RemoveScreenCaptureMonitorCallback");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(callback != nullptr, "RemoveScreenCaptureMonitorCallback failed, callback is nullptr");
    screenCaptureMonitorCbSet_.erase(callback);
    MEDIA_LOGI("0x%{public}06" PRIXPTR "RemoveScreenCaptureMonitorCallback OK.", FAKE_POINTER(this));
}

void ScreenCaptureMonitorServer::RegisterScreenCaptureMonitorListener(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> callback)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " RegisterScreenCaptureMonitorListener", FAKE_POINTER(this));
}

void ScreenCaptureMonitorServer::UnregisterScreenCaptureMonitorListener(
    sptr<ScreenCaptureMonitor::ScreenCaptureMonitorListener> listener)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " UnregisterScreenCaptureMonitorListener", FAKE_POINTER(this));
}

int32_t ScreenCaptureMonitorServer::CallOnScreenCaptureStarted(int32_t pid)
{
    MEDIA_LOGI("CallOnScreenCaptureStarted S");
    AddRunningCapturePid(pid);
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
    MEDIA_LOGI("CallOnScreenCaptureFinished S");
    RemoveRunningCapturePid(pid);
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

void ScreenCaptureMonitorServer::SetSystemScreenRecorderPid(int32_t pid)
{
    MEDIA_LOGI("SetSystemScreenRecorderPid pid: %{public}d", pid);
    std::lock_guard<std::mutex> lock(mutex_);
    systemScreenRecorderPid_ = pid;
}

bool ScreenCaptureMonitorServer::IsSystemScreenRecorder(int32_t pid)
{
    MEDIA_LOGI("IsSystemScreenRecorder S");
    if (pid < 0) {
        MEDIA_LOGW("IsSystemScreenRecorder invalid pid: %{public}d", pid);
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bool result = pid == systemScreenRecorderPid_;
    MEDIA_LOGI("IsSystemScreenRecorder result: %{public}d", result);
    return result;
}

bool ScreenCaptureMonitorServer::IsSystemScreenRecorderWorking()
{
    MEDIA_LOGI("IsSystemScreenRecorderWorking S");
    std::lock_guard<std::mutex> lock(mutex_);
    bool result = runningCapturePidCounts_.find(systemScreenRecorderPid_) != runningCapturePidCounts_.end();
    MEDIA_LOGI("IsSystemScreenRecorderWorking result: %{public}d", result);
    return result;
}
} // namespace Media
} // namespace OHOS
