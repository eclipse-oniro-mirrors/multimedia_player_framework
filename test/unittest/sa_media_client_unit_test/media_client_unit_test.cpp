/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "media_client_unit_test.h"
#include <thread>
#include "avmetadatahelper_client.h"
#include "i_standard_avmetadatahelper_service.h"
#include "player_client.h"
#include "i_avmetadatahelper_service.h"
#include "i_standard_recorder_profiles_service.h"
#include "media_errors.h"
#include "recorder_client.h"
#include "recorder_profiles_client.h"
#include "screen_capture_client.h"
#include "screen_capture_controller_client.h"
#include "screen_capture_monitor_client.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

namespace {
constexpr size_t OVER_MAX_PID_LIST_SIZE = 1001;

class MockStandardMediaService : public IRemoteStub<IStandardMediaService> {
public:
    sptr<IRemoteObject> GetSubSystemAbility(IStandardMediaService::MediaSystemAbility subSystemId,
        const sptr<IRemoteObject> &listener) override
    {
        lastSubSystemId = subSystemId;
        (void)listener;
        return subSystemObj;
    }

    sptr<IRemoteObject> GetSubSystemAbilityWithTimeOut(IStandardMediaService::MediaSystemAbility subSystemId,
        const sptr<IRemoteObject> &listener, uint32_t timeoutMs) override
    {
        lastSubSystemId = subSystemId;
        lastTimeoutMs = timeoutMs;
        (void)listener;
        return subSystemObj;
    }

    void ReleaseClientListener() override
    {
        releaseClientListenerCalled = true;
    }

    bool CanKillMediaService() override
    {
        return canKillMediaServiceRet;
    }

    std::vector<pid_t> GetPlayerPids() override
    {
        return playerPidsRet;
    }

    int32_t FreezeStubForPids(const std::set<int32_t> &pidList, bool isProxy) override
    {
        lastFreezePids = pidList;
        lastIsProxy = isProxy;
        return freezeRet;
    }

    int32_t ResetAllProxy() override
    {
        resetAllProxyCalled = true;
        return resetAllProxyRet;
    }

    int32_t GetLppCapacity(LppAvCapabilityInfo &lppAvCapability) override
    {
        (void)lppAvCapability;
        return lppCapacityRet;
    }

    sptr<IRemoteObject> subSystemObj = nullptr;
    IStandardMediaService::MediaSystemAbility lastSubSystemId =
        IStandardMediaService::MediaSystemAbility::MEDIA_PLAYER;
    uint32_t lastTimeoutMs = 0;
    bool releaseClientListenerCalled = false;
    bool canKillMediaServiceRet = true;
    std::vector<pid_t> playerPidsRet;
    std::set<int32_t> lastFreezePids;
    bool lastIsProxy = false;
    int32_t freezeRet = MSERR_OK;
    bool resetAllProxyCalled = false;
    int32_t resetAllProxyRet = MSERR_OK;
    int32_t lppCapacityRet = MSERR_OK;
};

void AttachMockProxy(const std::shared_ptr<MediaClient> &client, const sptr<MockStandardMediaService> &mock)
{
    client->mediaProxy_ = mock;
    client->weakProxy_ = mock;
    client->listenerStub_ = new (std::nothrow) MediaListenerStub();
}
} // namespace


void MediaClientUnitTest::SetUpTestCase(void)
{
}

void MediaClientUnitTest::TearDownTestCase(void)
{
}

void MediaClientUnitTest::SetUp(void)
{
}

void MediaClientUnitTest::TearDown(void)
{
}

/**
 * @tc.name  : Test PlayerMemManage AVPlayerServerDied API
 * @tc.number: MediaClientUnitTest_AVPlayerServerDied_test_001
 * @tc.desc  : Test PlayerMemManage AVPlayerServerDied interface
 */
HWTEST_F(MediaClientUnitTest, MediaClientUnitTest_AVPlayerServerDied_test_001, TestSize.Level0)
{
    std::shared_ptr<MediaClient> testptr = std::make_shared<MediaClient>();
    ASSERT_NE(testptr, nullptr);
    sptr<IStandardPlayerService> ipcProxy1;
    std::shared_ptr<IPlayerService> ptr1 = std::make_shared<PlayerClient>(ipcProxy1);
    sptr<IStandardAVMetadataHelperService> ipcProxy;
    std::shared_ptr<IAVMetadataHelperService> ptr2 = std::make_shared<AVMetadataHelperClient>(ipcProxy);
#define SUPPORT_PLAYER
#define SUPPORT_METADATA
    testptr->playerClientList_.push_back(ptr1);
    testptr->avMetadataHelperClientList_.push_back(ptr2);
    testptr->AVPlayerServerDied();
    EXPECT_EQ(testptr->playerClientList_.empty(), false);
#undef SUPPORT_PLAYER
#undef SUPPORT_METADATA
}

HWTEST_F(MediaClientUnitTest, MediaClientUnitTest_SeekToDefaultPosition_test_001, TestSize.Level0)
{
    sptr<IStandardPlayerService> ipcProxy;
    auto playerClient = std::make_shared<PlayerClient>(ipcProxy);
    ASSERT_NE(playerClient, nullptr);
    int32_t ret = playerClient->SeekToDefaultPosition();
    EXPECT_EQ(ret, MSERR_SERVICE_DIED);
}

HWTEST_F(MediaClientUnitTest, MediaClientUnitTest_GetSeekableRanges_test_001, TestSize.Level0)
{
    sptr<IStandardPlayerService> ipcProxy;
    auto playerClient = std::make_shared<PlayerClient>(ipcProxy);
    ASSERT_NE(playerClient, nullptr);
    std::vector<Plugins::SeekRange> seekableRanges;
    int32_t ret = playerClient->GetSeekableRanges(seekableRanges);
    EXPECT_EQ(ret, MSERR_SERVICE_DIED);
}

HWTEST_F(MediaClientUnitTest, MediaClientUnitTest_GetLoadedRanges_test_001, TestSize.Level0)
{
    sptr<IStandardPlayerService> ipcProxy;
    auto playerClient = std::make_shared<PlayerClient>(ipcProxy);
    ASSERT_NE(playerClient, nullptr);
    std::vector<Plugins::SeekRange> loadedRanges;
    int32_t ret = playerClient->GetLoadedRanges(loadedRanges);
    EXPECT_EQ(ret, MSERR_SERVICE_DIED);
}

HWTEST_F(MediaClientUnitTest, MediaClientUnitTest_IsLiveSeek_test_001, TestSize.Level0)
{
    sptr<IStandardPlayerService> ipcProxy;
    auto playerClient = std::make_shared<PlayerClient>(ipcProxy);
    ASSERT_NE(playerClient, nullptr);
    bool ret = playerClient->IsLiveSeek();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name  : MediaClient_GetInstance_001
 * @tc.number: MediaClient_GetInstance_001
 * @tc.desc  : Test MediaServiceFactory::GetInstance returns same singleton
 */
HWTEST_F(MediaClientUnitTest, MediaClient_GetInstance_001, TestSize.Level1)
{
    IMediaService &inst1 = MediaServiceFactory::GetInstance();
    IMediaService &inst2 = MediaServiceFactory::GetInstance();
    EXPECT_EQ(&inst1, &inst2);
}

/**
 * @tc.name  : MediaClient_ProxyForFreeze_001
 * @tc.number: MediaClient_ProxyForFreeze_001
 * @tc.desc  : Test ProxyForFreeze forwards valid pidList and rejects oversized pidList
 */
HWTEST_F(MediaClientUnitTest, MediaClient_ProxyForFreeze_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    std::set<int32_t> pidList = {100, 200};
    mock->freezeRet = MSERR_OK;
    EXPECT_EQ(client->ProxyForFreeze(pidList, true), MSERR_OK);
    EXPECT_EQ(mock->lastFreezePids, pidList);
    EXPECT_TRUE(mock->lastIsProxy);

    std::set<int32_t> oversizedPids;
    for (size_t i = 0; i < OVER_MAX_PID_LIST_SIZE; ++i) {
        oversizedPids.insert(static_cast<int32_t>(i));
    }
    EXPECT_EQ(client->ProxyForFreeze(oversizedPids, false), MSERR_INVALID_VAL);
}

/**
 * @tc.name  : MediaClient_ResetAllProxy_001
 * @tc.number: MediaClient_ResetAllProxy_001
 * @tc.desc  : Test ResetAllProxy delegates to media proxy
 */
HWTEST_F(MediaClientUnitTest, MediaClient_ResetAllProxy_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    mock->resetAllProxyRet = MSERR_OK;
    EXPECT_EQ(client->ResetAllProxy(), MSERR_OK);
    EXPECT_TRUE(mock->resetAllProxyCalled);
}

/**
 * @tc.name  : MediaClient_ReleaseClientListener_001
 * @tc.number: MediaClient_ReleaseClientListener_001
 * @tc.desc  : Test ReleaseClientListener returns false when proxy is null and true when valid
 */
HWTEST_F(MediaClientUnitTest, MediaClient_ReleaseClientListener_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    EXPECT_FALSE(client->ReleaseClientListener());

    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    EXPECT_TRUE(client->ReleaseClientListener());
    EXPECT_TRUE(mock->releaseClientListenerCalled);
    EXPECT_EQ(client->mediaProxy_, nullptr);
    EXPECT_EQ(client->listenerStub_, nullptr);
    EXPECT_EQ(client->deathRecipient_, nullptr);
}

/**
 * @tc.name  : MediaClient_CanKillMediaService_001
 * @tc.number: MediaClient_CanKillMediaService_001
 * @tc.desc  : Test CanKillMediaService returns proxy result and false when mutex is locked
 */
HWTEST_F(MediaClientUnitTest, MediaClient_CanKillMediaService_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    mock->canKillMediaServiceRet = true;
    EXPECT_TRUE(client->CanKillMediaService());

    mock->canKillMediaServiceRet = false;
    EXPECT_FALSE(client->CanKillMediaService());

    // Lock mutex from another thread so try_to_lock fails immediately
    std::unique_lock<std::mutex> lock(client->mutex_);
    bool resultWhileLocked = true;
    std::thread t([&client, &resultWhileLocked]() {
        resultWhileLocked = client->CanKillMediaService();
    });
    t.join();
    EXPECT_FALSE(resultWhileLocked);
}

/**
 * @tc.name  : MediaClient_GetPlayerPids_001
 * @tc.number: MediaClient_GetPlayerPids_001
 * @tc.desc  : Test GetPlayerPids returns pids from media proxy
 */
HWTEST_F(MediaClientUnitTest, MediaClient_GetPlayerPids_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    mock->playerPidsRet = {111, 222, 333};
    std::vector<pid_t> pids = client->GetPlayerPids();
    EXPECT_EQ(pids, mock->playerPidsRet);
}

/**
 * @tc.name  : MediaClient_GetMonitorProxy_001
 * @tc.number: MediaClient_GetMonitorProxy_001
 * @tc.desc  : Test GetMonitorProxy handles null and invalid remote object
 */
HWTEST_F(MediaClientUnitTest, MediaClient_GetMonitorProxy_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    mock->subSystemObj = nullptr;
    EXPECT_EQ(client->GetMonitorProxy(), nullptr);
    EXPECT_EQ(mock->lastSubSystemId, IStandardMediaService::MediaSystemAbility::MEDIA_MONITOR);

    // Non-monitor object should fail iface_cast
    mock->subSystemObj = client->listenerStub_->AsObject();
    EXPECT_EQ(client->GetMonitorProxy(), nullptr);
}

/**
 * @tc.name  : MediaClient_CreateDestroyServices_001
 * @tc.number: MediaClient_CreateDestroyServices_001
 * @tc.desc  : Test Create/Destroy service methods for null object, invalid object, and client removal
 */
HWTEST_F(MediaClientUnitTest, MediaClient_CreateDestroyServices_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);

    mock->subSystemObj = nullptr;
#define SUPPORT_PLAYER
#define SUPPORT_METADATA
#define SUPPORT_RECORDER
#define SUPPORT_SCREEN_CAPTURE
    EXPECT_EQ(client->CreatePlayerService(), nullptr);
    EXPECT_EQ(client->DestroyPlayerService(nullptr), MSERR_NO_MEMORY);
    auto playerClient = std::make_shared<PlayerClient>(nullptr);
    client->playerClientList_.push_back(playerClient);
    EXPECT_EQ(client->DestroyPlayerService(playerClient), MSERR_OK);
    EXPECT_TRUE(client->playerClientList_.empty());

    EXPECT_EQ(client->CreateAVMetadataHelperService(), nullptr);
    EXPECT_EQ(client->DestroyAVMetadataHelperService(nullptr), MSERR_NO_MEMORY);
    auto metaClient = std::make_shared<AVMetadataHelperClient>(nullptr);
    client->avMetadataHelperClientList_.push_back(metaClient);
    EXPECT_EQ(client->DestroyAVMetadataHelperService(metaClient), MSERR_OK);
    EXPECT_TRUE(client->avMetadataHelperClientList_.empty());

    EXPECT_EQ(client->CreateRecorderService(), nullptr);
    EXPECT_EQ(client->DestroyRecorderService(nullptr), MSERR_NO_MEMORY);
    auto recClient = std::make_shared<RecorderClient>(nullptr);
    client->recorderClientList_.push_back(recClient);
    EXPECT_EQ(client->DestroyRecorderService(recClient), MSERR_OK);
    EXPECT_TRUE(client->recorderClientList_.empty());

    EXPECT_EQ(client->CreateRecorderProfilesService(), nullptr);
    EXPECT_EQ(client->DestroyMediaProfileService(nullptr), MSERR_NO_MEMORY);
    auto profClient = std::make_shared<RecorderProfilesClient>(nullptr);
    client->recorderProfilesClientList_.push_back(profClient);
    EXPECT_EQ(client->DestroyMediaProfileService(profClient), MSERR_OK);
    EXPECT_TRUE(client->recorderProfilesClientList_.empty());

    EXPECT_EQ(client->CreateScreenCaptureService(), nullptr);
    EXPECT_EQ(client->DestroyScreenCaptureService(nullptr), MSERR_NO_MEMORY);
    auto scClient = std::make_shared<ScreenCaptureClient>(nullptr);
    client->screenCaptureClientList_.push_back(scClient);
    EXPECT_EQ(client->DestroyScreenCaptureService(scClient), MSERR_OK);
    EXPECT_TRUE(client->screenCaptureClientList_.empty());

    EXPECT_EQ(client->CreateScreenCaptureMonitorService(), nullptr);
    EXPECT_EQ(client->DestroyScreenCaptureMonitorService(nullptr), MSERR_NO_MEMORY);
    auto scmClient = std::make_shared<ScreenCaptureMonitorClient>(nullptr);
    client->screenCaptureMonitorClientList_.push_back(scmClient);
    EXPECT_EQ(client->DestroyScreenCaptureMonitorService(scmClient), MSERR_OK);
    EXPECT_TRUE(client->screenCaptureMonitorClientList_.empty());

    EXPECT_EQ(client->CreateScreenCaptureControllerClient(), nullptr);
    EXPECT_EQ(client->DestroyScreenCaptureControllerClient(nullptr), MSERR_NO_MEMORY);
    auto sccClient = std::make_shared<ScreenCaptureControllerClient>(nullptr);
    client->screenCaptureControllerList_.push_back(sccClient);
    EXPECT_EQ(client->DestroyScreenCaptureControllerClient(sccClient), MSERR_OK);
    EXPECT_TRUE(client->screenCaptureControllerList_.empty());
#undef SUPPORT_PLAYER
#undef SUPPORT_METADATA
#undef SUPPORT_RECORDER
#undef SUPPORT_SCREEN_CAPTURE
}

/**
 * @tc.name  : MediaClient_DoMediaServerDied_001
 * @tc.number: MediaClient_DoMediaServerDied_001
 * @tc.desc  : Test DoMediaServerDied notifies all client lists and clears proxy state
 */
HWTEST_F(MediaClientUnitTest, MediaClient_DoMediaServerDied_001, TestSize.Level1)
{
    auto client = std::make_shared<MediaClient>();
    sptr<MockStandardMediaService> mock = new (std::nothrow) MockStandardMediaService();
    ASSERT_NE(mock, nullptr);
    AttachMockProxy(client, mock);
    client->deathRecipient_ = new (std::nothrow) MediaDeathRecipient(0);

#define SUPPORT_PLAYER
#define SUPPORT_METADATA
#define SUPPORT_RECORDER
#define SUPPORT_SCREEN_CAPTURE
    client->playerClientList_.push_back(std::make_shared<PlayerClient>(nullptr));
    client->playerClientList_.push_back(nullptr);
    client->avMetadataHelperClientList_.push_back(std::make_shared<AVMetadataHelperClient>(nullptr));
    client->recorderClientList_.push_back(std::make_shared<RecorderClient>(nullptr));
    client->recorderProfilesClientList_.push_back(std::make_shared<RecorderProfilesClient>(nullptr));
    client->screenCaptureClientList_.push_back(std::make_shared<ScreenCaptureClient>(nullptr));
    client->screenCaptureMonitorClientList_.push_back(std::make_shared<ScreenCaptureMonitorClient>(nullptr));
    client->screenCaptureControllerList_.push_back(std::make_shared<ScreenCaptureControllerClient>(nullptr));
#undef SUPPORT_PLAYER
#undef SUPPORT_METADATA
#undef SUPPORT_RECORDER
#undef SUPPORT_SCREEN_CAPTURE

    client->DoMediaServerDied();

    EXPECT_EQ(client->mediaProxy_, nullptr);
    EXPECT_EQ(client->listenerStub_, nullptr);
    EXPECT_EQ(client->deathRecipient_, nullptr);
}
} // namespace Media
} // namespace OHOS