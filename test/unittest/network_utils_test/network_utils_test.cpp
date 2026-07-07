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

#include "network_utils_test.h"
#include "network_utils.cpp"

using namespace testing;
using namespace testing::Ext;

namespace OHOS {
namespace Media {

HWTEST_F(NetworkUtilsTest, GetInstance_SingleInstance_001, TestSize.Level0)
{
    NetworkUtils& instance1 = NetworkUtils::GetInstance();
    NetworkUtils& instance2 = NetworkUtils::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

HWTEST_F(NetworkUtilsTest, GetCurrentNetworkType_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    bool isWifi = utils.IsWifiConnected();
    bool isCellular = utils.IsCellularConnected();
    bool isEthernet = utils.IsEthernetConnected();
    bool isBluetooth = utils.IsBluetoothConnected();
    bool isVpn = utils.IsVpnConnected();
    switch (type) {
        case NET_CONN_WIFI:
            EXPECT_TRUE(isWifi);
            break;
        case NET_CONN_CELLULAR:
            EXPECT_TRUE(isCellular);
            break;
        case NET_CONN_ETHERNET:
            EXPECT_TRUE(isEthernet);
            break;
        case NET_CONN_BLUETOOTH:
            EXPECT_TRUE(isBluetooth);
            break;
        case NET_CONN_VPN:
            EXPECT_TRUE(isVpn);
            break;
        case NET_CONN_NONE:
            EXPECT_FALSE(isWifi || isCellular || isEthernet || isBluetooth || isVpn);
            break;
        default:
            break;
    }
}

HWTEST_F(NetworkUtilsTest, IsEthernetConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    bool result = utils.IsEthernetConnected();
    if (type == NET_CONN_ETHERNET) {
        EXPECT_TRUE(result);
    } else {
        EXPECT_FALSE(result);
    }
}

HWTEST_F(NetworkUtilsTest, IsBluetoothConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    bool result = utils.IsBluetoothConnected();
    if (type == NET_CONN_BLUETOOTH) {
        EXPECT_TRUE(result);
    } else {
        EXPECT_FALSE(result);
    }
}

HWTEST_F(NetworkUtilsTest, IsVpnConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    bool result = utils.IsVpnConnected();
    if (type == NET_CONN_VPN) {
        EXPECT_TRUE(result);
    } else {
        EXPECT_FALSE(result);
    }
}

HWTEST_F(NetworkUtilsTest, IsNetworkAvailable_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    bool result = utils.IsNetworkAvailable();
    if (type == NET_CONN_NONE || type == NET_CONN_UNKNOWN) {
        EXPECT_FALSE(result);
    } else {
        EXPECT_TRUE(result);
    }
}

HWTEST_F(NetworkUtilsTest, IsDefaultNetMetered_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    bool result = utils.IsDefaultNetMetered();
    if (type == NET_CONN_CELLULAR) {
        EXPECT_TRUE(result);
    } else if (type == NET_CONN_WIFI || type == NET_CONN_ETHERNET) {
        EXPECT_FALSE(result);
    }
}

HWTEST_F(NetworkUtilsTest, GetConnectionProperties_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    NetConnType type = utils.GetCurrentNetworkType();
    ConnProperties props = utils.GetConnectionProperties();
    if (type != NET_CONN_NONE && type != NET_CONN_UNKNOWN) {
        EXPECT_FALSE(props.ifaceName.empty());
    }
}

HWTEST_F(NetworkUtilsTest, NetConnType_Values_001, TestSize.Level0)
{
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_UNKNOWN), 0);
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_CELLULAR), 1);
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_WIFI), 2);
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_BLUETOOTH), 3);
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_ETHERNET), 4);
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_VPN), 5);
    EXPECT_EQ(static_cast<int32_t>(NetConnType::NET_CONN_NONE), 6);
}

HWTEST_F(NetworkUtilsTest, ConnProperties_Struct_001, TestSize.Level0)
{
    ConnProperties props;
    props.ifaceName = "eth0";
    props.domain = "example.com";
    props.dnsList = {"8.8.8.8", "8.8.4.4"};
    props.netAddrList = {"192.168.1.1"};
    props.mtu = 1500;

    EXPECT_EQ(props.ifaceName, "eth0");
    EXPECT_EQ(props.domain, "example.com");
    EXPECT_EQ(props.dnsList.size(), 2);
    EXPECT_EQ(props.netAddrList.size(), 1);
    EXPECT_EQ(props.mtu, 1500);
}

HWTEST_F(NetworkUtilsTest, NetworkChangeCallback_Type_001, TestSize.Level0)
{
    NetworkChangeCallback callback = [](NetConnType type) {
        EXPECT_TRUE(type >= NetConnType::NET_CONN_UNKNOWN && type <= NetConnType::NET_CONN_NONE);
    };
    callback(NetConnType::NET_CONN_WIFI);
}

} // namespace Media
} // namespace OHOS
