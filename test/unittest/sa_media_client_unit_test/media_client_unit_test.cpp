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
#include "avmetadatahelper_client.h"
#include "i_standard_avmetadatahelper_service.h"
#include "player_client.h"
#include "i_avmetadatahelper_service.h"
#include "i_standard_recorder_profiles_service.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;


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
} // namespace Media
} // namespace OHOS