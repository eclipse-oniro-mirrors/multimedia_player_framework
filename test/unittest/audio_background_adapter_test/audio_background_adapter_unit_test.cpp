/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
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

#include "audio_background_adapter_unit_test.h"
#include <unistd.h>
#include <chrono>
#include <thread>
#include <memory>
#include "player.h"
#include "player_server.h"
#include "media_dfx.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace Test {
using namespace std;
using namespace testing::ext;
constexpr int32_t CONSTRUCTED_UID_1 = 999999;
constexpr int32_t CONSTRUCTED_UID_2 = 1000000;
void AudioBackGroundAdapterUnitTest::SetUpTestCase(void) {}
 
void AudioBackGroundAdapterUnitTest::TearDownTestCase(void) {}
 
void AudioBackGroundAdapterUnitTest::SetUp(void) {}
 
void AudioBackGroundAdapterUnitTest::TearDown(void) {}

/**
 * @tc.name  : AddListener
 * @tc.number: AddListener
 * @tc.desc  : FUNC
 */
HWTEST_F(AudioBackGroundAdapterUnitTest, AddListener, TestSize.Level1)
{
    auto playerServer = PlayerServer::Create();
    EXPECT_NE(playerServer, nullptr);
    AudioBackgroundAdapter::Instance().AddListener(playerServer, CONSTRUCTED_UID_1);
    playerServer = nullptr;
    auto playerServer2 = PlayerServer::Create();
    EXPECT_NE(playerServer2, nullptr);
    AudioBackgroundAdapter::Instance().AddListener(playerServer2, CONSTRUCTED_UID_1);
    auto playerServer3 = PlayerServer::Create();
    EXPECT_NE(playerServer3, nullptr);
    AudioBackgroundAdapter::Instance().AddListener(playerServer3, CONSTRUCTED_UID_1);
    EXPECT_NE(AudioBackgroundAdapter::Instance().playerMap_.size(), 0);
    playerServer2 = nullptr;
    playerServer3 = nullptr;
}

/**
 * @tc.name  : OnBackgroundMute
 * @tc.number: OnBackgroundMute
 * @tc.desc  : FUNC
 */
HWTEST_F(AudioBackGroundAdapterUnitTest, OnBackgroundMute, TestSize.Level1)
{
    auto playerServer = std::static_pointer_cast<PlayerServer>(PlayerServer::Create());
    ASSERT_NE(playerServer, nullptr);
    playerServer->lastOpStatus_ = PLAYER_STARTED;
    AudioBackgroundAdapter::Instance().AddListener(playerServer, CONSTRUCTED_UID_2);
    AudioBackgroundAdapter::Instance().OnBackgroundMute(CONSTRUCTED_UID_2);
    AudioBackgroundAdapter::Instance().OnAudioRestart();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

}  // namespace Test
}  // namespace Media
}  // namespace OHOS