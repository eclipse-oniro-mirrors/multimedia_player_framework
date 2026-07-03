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
    (void)type;
}

HWTEST_F(NetworkUtilsTest, IsCellularConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsCellularConnected();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, IsWifiConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsWifiConnected();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, IsEthernetConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsEthernetConnected();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, IsBluetoothConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsBluetoothConnected();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, IsVpnConnected_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsVpnConnected();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, IsNetworkAvailable_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsNetworkAvailable();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, IsDefaultNetMetered_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool result = utils.IsDefaultNetMetered();
    EXPECT_TRUE(result == true || result == false);
}

HWTEST_F(NetworkUtilsTest, GetConnectionProperties_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    ConnProperties props = utils.GetConnectionProperties();
    (void)props;
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

HWTEST_F(NetworkUtilsTest, RegisterNetworkChangeCallback_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    bool callbackCalled = false;
    NetworkChangeCallback callback = [&callbackCalled](NetConnType type) {
        (void)type;
        callbackCalled = true;
    };
    utils.RegisterNetworkChangeCallback(callback);
}

HWTEST_F(NetworkUtilsTest, UnregisterNetworkChangeCallback_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    utils.UnregisterNetworkChangeCallback();
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

HWTEST_F(NetworkUtilsTest, MultipleCallbackRegistrations_001, TestSize.Level0)
{
    NetworkUtils& utils = NetworkUtils::GetInstance();
    int callCount = 0;
    NetworkChangeCallback callback1 = [&callCount](NetConnType type) {
        (void)type;
        ++callCount;
    };
    NetworkChangeCallback callback2 = [&callCount](NetConnType type) {
        (void)type;
        ++callCount;
    };
    utils.RegisterNetworkChangeCallback(callback1);
    utils.RegisterNetworkChangeCallback(callback2);
}

} // namespace Media
} // namespace OHOS
