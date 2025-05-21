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

#include "media_server_test.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
static const int32_t SYSTEM_ABILITY_ID = 1910;
void MediaServerTest::SetUpTestCase(void)
{
}

void MediaServerTest::TearDownTestCase(void)
{
}

void MediaServerTest::SetUp(void)
{
}

void MediaServerTest::TearDown(void)
{
}

/**
 * @tc.name  : GetSubSystemAbility_001
 * @tc.number: GetSubSystemAbility_001
 * @tc.desc  : Test GetSubSystemAbility interface
 */
HWTEST_F(MediaServerTest, GetSubSystemAbility_001, TestSize.Level1)
{
    MediaServer mediaServer(0, true);
    std::shared_ptr<MockMediaServerManager> mockMediaServerManager = std::make_shared<MockMediaServerManager>();
    sptr<IRemoteObject> object = nullptr;
    EXPECT_CALL(*mockMediaServerManager, CreateRecorderStubObject())
        .WillRepeatedly(testing::Return(object));
    sptr<IRemoteObject> listener = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
    std::shared_ptr<MockMediaServiceStub> mock = std::make_shared<MockMediaServiceStub>();
    EXPECT_CALL(*mock, SetDeathListener(listener)).WillRepeatedly(testing::Return(MSERR_OK));
    sptr<IRemoteObject> ret = mediaServer.GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_CODECLIST, listener);
    EXPECT_EQ(ret, nullptr);
    listener = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
    ret = mediaServer.GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_AVCODEC, listener);
    EXPECT_EQ(ret, nullptr);
    listener = MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
    EXPECT_NE(listener, nullptr);
    ret = mediaServer.GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::RECORDER_PROFILES, listener);
    EXPECT_EQ(ret, nullptr);
    ret = mediaServer.GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_CODEC, listener);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name  : OnAddSystemAbility_001
 * @tc.number: OnAddSystemAbility_001
 * @tc.desc  : Test OnAddSystemAbility interface
 */
HWTEST_F(MediaServerTest, OnAddSystemAbility_001, TestSize.Level1)
{
    MediaServer mediaServer(0, true);
    int32_t systemAbilityId = MEMORY_MANAGER_SA_ID + 1;
    std::string deviceId = "deviceId";
    mediaServer.OnAddSystemAbility(systemAbilityId, deviceId);
    EXPECT_EQ(systemAbilityId, SYSTEM_ABILITY_ID);
}
} // namespace Media
} // namespace OHOS
