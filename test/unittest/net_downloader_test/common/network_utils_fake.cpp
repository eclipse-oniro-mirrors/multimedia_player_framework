/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "network_utils_fake.h"

#include <atomic>

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

namespace {
std::atomic<NetConnType> g_fakeType{NET_CONN_NONE};
}

void SetFakeNetworkType(NetConnType type)
{
    g_fakeType.store(type);
}

NetConnType GetFakeNetworkType()
{
    return g_fakeType.load();
}

void ResetFakeNetworkType()
{
    g_fakeType.store(NET_CONN_NONE);
}

NetworkUtils::NetworkUtils() = default;
NetworkUtils::~NetworkUtils() = default;

NetworkUtils &NetworkUtils::GetInstance()
{
    static NetworkUtils instance;
    return instance;
}

NetConnType NetworkUtils::GetCurrentNetworkType()
{
    return g_fakeType.load();
}

bool NetworkUtils::IsCellularConnected()
{
    return false;
}

bool NetworkUtils::IsWifiConnected()
{
    return false;
}

bool NetworkUtils::IsEthernetConnected()
{
    return false;
}

bool NetworkUtils::IsBluetoothConnected()
{
    return false;
}

bool NetworkUtils::IsVpnConnected()
{
    return false;
}

bool NetworkUtils::IsNetworkAvailable()
{
    return g_fakeType.load() != NET_CONN_NONE;
}

bool NetworkUtils::IsDefaultNetMetered()
{
    return false;
}

ConnProperties NetworkUtils::GetConnectionProperties()
{
    return {};
}

void NetworkUtils::RegisterNetworkChangeCallback(NetworkChangeCallback callback)
{
    (void)callback;
}

void NetworkUtils::UnregisterNetworkChangeCallback() {}

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS
