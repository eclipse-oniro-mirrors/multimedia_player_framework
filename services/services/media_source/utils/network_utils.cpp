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

#include "network_utils.h"

#include "common/log.h"
#include "net_conn_client.h"
#include "net_conn_callback_stub.h"
#include "net_all_capabilities.h"
#include "net_handle.h"
#include "net_link_info.h"
#include "net_conn_constants.h"
#include "refbase.h"

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

using namespace OHOS::NetManagerStandard;

namespace OHOS {
namespace Media {
namespace MediaSourceUtils {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetworkUtils"};

NetConnType ConvertBearerType(NetBearType bearerType)
{
    MEDIA_LOGI("ConvertBearerType, networkType: %{public}d", bearerType);
    switch (bearerType) {
        case BEARER_CELLULAR:
            return NET_CONN_CELLULAR;
        case BEARER_WIFI:
            return NET_CONN_WIFI;
        case BEARER_BLUETOOTH:
            return NET_CONN_BLUETOOTH;
        case BEARER_ETHERNET:
            return NET_CONN_ETHERNET;
        case BEARER_VPN:
            return NET_CONN_VPN;
        default:
            return NET_CONN_UNKNOWN;
    }
}
}

class NetConnCallbackImpl : public NetConnCallbackStub {
public:
    explicit NetConnCallbackImpl(NetworkUtils &owner) : owner_(owner) {}

    int32_t NetAvailable(sptr<NetHandle> &netHandle) override
    {
        MEDIA_LOGI("NetAvailable, netId: %{public}d", netHandle != nullptr ? netHandle->GetNetId() : -1);
        std::lock_guard<std::mutex> lock(owner_.mutex_);
        NetConnType newType = owner_.DetectNetworkType();
        owner_.NotifyCallback(newType);
        owner_.currentNetType_ = newType;
        return NETMANAGER_SUCCESS;
    }

    int32_t NetCapabilitiesChange(sptr<NetHandle> &netHandle,
        const sptr<NetAllCapabilities> &netAllCap) override
    {
        MEDIA_LOGI("NetCapabilitiesChange, netId: %{public}d", netHandle != nullptr ? netHandle->GetNetId() : -1);
        std::lock_guard<std::mutex> lock(owner_.mutex_);
        NetConnType newType = NET_CONN_UNKNOWN;
        if (netAllCap != nullptr && !netAllCap->bearerTypes_.empty()) {
            MEDIA_LOGI("NetCapabilitiesChange, netAllCap not null");
            newType = ConvertBearerType(*netAllCap->bearerTypes_.begin());
        }
        owner_.NotifyCallback(newType);
        owner_.currentNetType_ = newType;
        return NETMANAGER_SUCCESS;
    }

    int32_t NetConnectionPropertiesChange(sptr<NetHandle> &netHandle,
        const sptr<NetLinkInfo> &info) override
    {
        (void) netHandle;
        (void) info;
        return NETMANAGER_SUCCESS;
    }

    int32_t NetLost(sptr<NetHandle> &netHandle) override
    {
        MEDIA_LOGI("NetLost, netId: %{public}d", netHandle != nullptr ? netHandle->GetNetId() : -1);
        std::lock_guard<std::mutex> lock(owner_.mutex_);
        owner_.NotifyCallback(NET_CONN_NONE);
        owner_.currentNetType_ = NET_CONN_NONE;
        return NETMANAGER_SUCCESS;
    }

    int32_t NetUnavailable() override
    {
        MEDIA_LOGI("NetUnavailable");
        std::lock_guard<std::mutex> lock(owner_.mutex_);
        owner_.NotifyCallback(NET_CONN_NONE);
        owner_.currentNetType_ = NET_CONN_NONE;
        return NETMANAGER_SUCCESS;
    }

    int32_t NetBlockStatusChange(sptr<NetHandle> &netHandle, bool blocked) override
    {
        (void) netHandle;
        (void) blocked;
        return NETMANAGER_SUCCESS;
    }

private:
    NetworkUtils &owner_;
};

namespace {
sptr<NetConnCallbackImpl> g_netConnCallback = nullptr;
}

NetworkUtils& NetworkUtils::GetInstance()
{
    static NetworkUtils instance;
    return instance;
}

NetworkUtils::NetworkUtils()
    : currentNetType_(NET_CONN_NONE)
{
    RefreshNetworkState();
    MEDIA_LOGI("NetworkUtils created, initial type: %{public}d", currentNetType_);
}

NetworkUtils::~NetworkUtils()
{
    UnregisterNetworkChangeCallback();
    MEDIA_LOGI("NetworkUtils destroyed");
}

NetConnType NetworkUtils::DetectNetworkType()
{
    NetHandle netHandle;
    int32_t ret = NetConnClient::GetInstance().GetDefaultNet(netHandle);
    if (ret != NETMANAGER_SUCCESS) {
        MEDIA_LOGW("GetDefaultNet failed, ret: %{public}d", ret);
        return NET_CONN_NONE;
    }

    NetAllCapabilities netCaps;
    ret = NetConnClient::GetInstance().GetNetCapabilities(netHandle, netCaps);
    if (ret != NETMANAGER_SUCCESS) {
        MEDIA_LOGW("GetNetCapabilities failed, ret: %{public}d", ret);
        return NET_CONN_UNKNOWN;
    }

    if (netCaps.bearerTypes_.empty()) {
        MEDIA_LOGW("No bearer types found");
        return NET_CONN_UNKNOWN;
    }

    return ConvertBearerType(*netCaps.bearerTypes_.begin());
}

void NetworkUtils::RefreshNetworkState()
{
    currentNetType_ = DetectNetworkType();
}

NetConnType NetworkUtils::GetCurrentNetworkType()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RefreshNetworkState();
    return currentNetType_;
}

bool NetworkUtils::IsCellularConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RefreshNetworkState();
    return currentNetType_ == NET_CONN_CELLULAR;
}

bool NetworkUtils::IsWifiConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RefreshNetworkState();
    return currentNetType_ == NET_CONN_WIFI;
}

bool NetworkUtils::IsEthernetConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RefreshNetworkState();
    return currentNetType_ == NET_CONN_ETHERNET;
}

bool NetworkUtils::IsBluetoothConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RefreshNetworkState();
    return currentNetType_ == NET_CONN_BLUETOOTH;
}

bool NetworkUtils::IsVpnConnected()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RefreshNetworkState();
    return currentNetType_ == NET_CONN_VPN;
}

bool NetworkUtils::IsNetworkAvailable()
{
    bool hasDefaultNet = false;
    int32_t ret = NetConnClient::GetInstance().HasDefaultNet(hasDefaultNet);
    if (ret != NETMANAGER_SUCCESS) {
        MEDIA_LOGW("HasDefaultNet failed, ret: %{public}d", ret);
        return false;
    }
    return hasDefaultNet;
}

bool NetworkUtils::IsDefaultNetMetered()
{
    bool isMetered = false;
    int32_t ret = NetConnClient::GetInstance().IsDefaultNetMetered(isMetered);
    if (ret != NETMANAGER_SUCCESS) {
        MEDIA_LOGW("IsDefaultNetMetered failed, ret: %{public}d", ret);
        return false;
    }
    return isMetered;
}

ConnProperties NetworkUtils::GetConnectionProperties()
{
    std::lock_guard<std::mutex> lock(mutex_);
    ConnProperties props;

    NetHandle netHandle;
    int32_t ret = NetConnClient::GetInstance().GetDefaultNet(netHandle);
    if (ret != NETMANAGER_SUCCESS) {
        MEDIA_LOGW("GetDefaultNet failed, ret: %{public}d", ret);
        return props;
    }

    NetLinkInfo linkInfo;
    ret = NetConnClient::GetInstance().GetConnectionProperties(netHandle, linkInfo);
    if (ret != NETMANAGER_SUCCESS) {
        MEDIA_LOGW("GetConnectionProperties failed, ret: %{public}d", ret);
        return props;
    }

    props.ifaceName = linkInfo.ifaceName_;
    props.domain = linkInfo.domain_;
    props.mtu = linkInfo.mtu_;

    for (const auto &addr : linkInfo.dnsList_) {
        props.dnsList.emplace_back(addr.address_);
    }

    for (const auto &addr : linkInfo.netAddrList_) {
        props.netAddrList.emplace_back(addr.address_);
    }

    return props;
}

void NetworkUtils::NotifyCallback(NetConnType newType)
{
    MEDIA_LOGI("Network changed before: %{public}d -> %{public}d", currentNetType_, newType);
    if (networkChangeCallback_ != nullptr && currentNetType_ != newType) {
        MEDIA_LOGI("Network changed after: %{public}d -> %{public}d", currentNetType_, newType);
        networkChangeCallback_(newType);
    }
}

void NetworkUtils::RegisterNetworkChangeCallback(NetworkChangeCallback callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkChangeCallback_ = callback;

    if (!callbackRegistered_) {
        g_netConnCallback = sptr<NetConnCallbackImpl>::MakeSptr(*this);
        if (g_netConnCallback == nullptr) {
            MEDIA_LOGE("Failed to create NetConnCallbackImpl");
            return;
        }
        int32_t ret = NetConnClient::GetInstance().RegisterNetConnCallback(g_netConnCallback);
        if (ret != NETMANAGER_SUCCESS) {
            MEDIA_LOGE("RegisterNetConnCallback failed, ret: %{public}d", ret);
            g_netConnCallback = nullptr;
            return;
        }
        callbackRegistered_ = true;
        MEDIA_LOGI("Network change callback registered");
    }
}

void NetworkUtils::UnregisterNetworkChangeCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    networkChangeCallback_ = nullptr;

    if (callbackRegistered_ && g_netConnCallback != nullptr) {
        int32_t ret = NetConnClient::GetInstance().UnregisterNetConnCallback(g_netConnCallback);
        if (ret != NETMANAGER_SUCCESS) {
            MEDIA_LOGW("UnregisterNetConnCallback failed, ret: %{public}d", ret);
        }
        g_netConnCallback = nullptr;
        callbackRegistered_ = false;
        MEDIA_LOGI("Network change callback unregistered");
    }
}

} // namespace MediaSourceUtils
} // namespace Media
} // namespace OHOS