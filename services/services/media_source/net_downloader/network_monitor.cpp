/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "network_monitor.h"

#include "common/log.h"

#ifndef MEDIA_LOGD
#define MEDIA_LOGD MEDIA_LOG_D
#endif
#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif
#ifndef MEDIA_LOGE
#define MEDIA_LOGE MEDIA_LOG_E
#endif

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderNetworkMonitor"};
}

NetworkMonitor& NetworkMonitor::GetInstance()
{
    static NetworkMonitor instance;
    return instance;
}

NetworkMonitor::NetworkMonitor()
    : currentNetworkType_(NETWORK_WIFI)
{
    MEDIA_LOGI("NetworkMonitor created");
}

NetworkMonitor::~NetworkMonitor()
{
    MEDIA_LOGI("NetworkMonitor destroyed");
}

NetworkType NetworkMonitor::DetectNetworkType()
{
    MEDIA_LOGD("DetectNetworkType");
    return NETWORK_WIFI;
}

NetworkType NetworkMonitor::GetCurrentNetworkType()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentNetworkType_;
}

bool NetworkMonitor::IsWifiConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentNetworkType_ == NETWORK_WIFI;
}

bool NetworkMonitor::IsMobileDataConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentNetworkType_ == NETWORK_MOBILE_DATA;
}

bool NetworkMonitor::IsNetworkAvailable()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentNetworkType_ != NETWORK_NONE && currentNetworkType_ != NETWORK_UNKNOWN;
}

void NetworkMonitor::RegisterNetworkChangeCallback(NetworkChangeCallback callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkChangeCallback_ = callback;
    MEDIA_LOGI("RegisterNetworkChangeCallback");
}

void NetworkMonitor::UnregisterNetworkChangeCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkChangeCallback_ = nullptr;
    MEDIA_LOGI("UnregisterNetworkChangeCallback");
}

void NetworkMonitor::OnNetworkStateChanged()
{
    std::lock_guard<std::mutex> lock(mutex_);
    NetworkType oldType = currentNetworkType_;
    currentNetworkType_ = DetectNetworkType();

    if (oldType != currentNetworkType_ && networkChangeCallback_ != nullptr) {
        MEDIA_LOGI("Network changed: %{public}d -> %{public}d", oldType, currentNetworkType_);
        networkChangeCallback_(currentNetworkType_);
    }
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS