/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

enum NetworkType : int32_t {
    NETWORK_UNKNOWN = 0,
    NETWORK_WIFI,
    NETWORK_MOBILE_DATA,
    NETWORK_NONE,
};

class NetworkMonitor : public NoCopyable {
public:
    using NetworkChangeCallback = std::function<void(NetworkType)>;

    static NetworkMonitor& GetInstance();

    NetworkType GetCurrentNetworkType();
    bool IsWifiConnected();
    bool IsMobileDataConnected();
    bool IsNetworkAvailable();
    
    void RegisterNetworkChangeCallback(NetworkChangeCallback callback);
    void UnregisterNetworkChangeCallback();

private:
    NetworkMonitor();
    ~NetworkMonitor();

    NetworkType DetectNetworkType();
    void OnNetworkStateChanged();

    NetworkType currentNetworkType_;
    NetworkChangeCallback networkChangeCallback_;
    std::mutex mutex_;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // NETWORK_MONITOR_H