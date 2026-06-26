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

#ifndef MEDIA_SOURCE_NETWORK_UTILS_H
#define MEDIA_SOURCE_NETWORK_UTILS_H

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

enum NetConnType : int32_t {
    NET_CONN_UNKNOWN = 0,
    NET_CONN_CELLULAR,
    NET_CONN_WIFI,
    NET_CONN_BLUETOOTH,
    NET_CONN_ETHERNET,
    NET_CONN_VPN,
    NET_CONN_NONE,
};

struct ConnProperties {
    std::string ifaceName;
    std::string domain;
    std::vector<std::string> dnsList;
    std::vector<std::string> netAddrList;
    uint16_t mtu = 0;
};

class NetConnCallbackImpl;

class NetworkUtils : public NoCopyable {
public:
    using NetworkChangeCallback = std::function<void(NetConnType)>;

    static NetworkUtils& GetInstance();

    NetConnType GetCurrentNetworkType();
    bool IsCellularConnected();
    bool IsWifiConnected();
    bool IsEthernetConnected();
    bool IsBluetoothConnected();
    bool IsVpnConnected();
    bool IsNetworkAvailable();
    bool IsDefaultNetMetered();
    ConnProperties GetConnectionProperties();

    void RegisterNetworkChangeCallback(NetworkChangeCallback callback);
    void UnregisterNetworkChangeCallback();

private:
    NetworkUtils();
    ~NetworkUtils();

    friend class NetConnCallbackImpl;

    NetConnType DetectNetworkType();
    void RefreshNetworkState();
    void NotifyCallback(NetConnType newType);

    NetConnType currentNetType_;
    NetworkChangeCallback networkChangeCallback_;
    bool callbackRegistered_ = false;
    std::mutex mutex_;
};

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SOURCE_NETWORK_UTILS_H