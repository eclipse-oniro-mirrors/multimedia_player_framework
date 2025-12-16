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

#include "sound_id_manager_unittest.h"
#include "media_errors.h"
#include "sound_id_manager.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Media {
static const int32_t ID_TEST = 10;
static const int32_t NUM_TEST = 1;
static const int32_t LENGTH_TEST = 10;
static const int32_t MAX_NUM = 33;
static const int32_t MSERR_INVALID = -1;
void SoundIDManagerUnittest::SetUpTestCase(void)
{}

void SoundIDManagerUnittest::TearDownTestCase(void)
{}

void SoundIDManagerUnittest::SetUp(void)
{
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    soundIDManager_ = std::make_shared<SoundIDManager>();
}

void SoundIDManagerUnittest::TearDown(void)
{
    soundIDManager_ = nullptr;
}

/**
 * @tc.name  : Test Load
 * @tc.number: SoundIdLoad_001
 * @tc.desc  : Test apiVersion > 0 && apiVersion < SOUNDPOOL_API_VERSION_ISOLATION
 */
HWTEST_F(SoundIDManagerUnittest, SoundIdLoad_001, TestSize.Level0)
{
    int32_t fd = ID_TEST;
    int64_t offset = 0;
    int64_t length = LENGTH_TEST;
    soundIDManager_->SetApiVersion(NUM_TEST);
    for (int32_t i = 0; i <= MAX_NUM; ++i)
    {
        soundIDManager_->soundParsers_[i] = nullptr;
    }
    EXPECT_EQ(MSERR_INVALID, soundIDManager_->Load(fd, offset, length));
}

/**
 * @tc.name  : Test Load
 * @tc.number: SoundIdLoad_002
 * @tc.desc  : Test apiVersion > 0 && apiVersion < SOUNDPOOL_API_VERSION_ISOLATION
 */
HWTEST_F(SoundIDManagerUnittest, SoundIdLoad_002, TestSize.Level0)
{
    std::string testUrl = "testUri";
    int32_t apiVersion = NUM_TEST;
    soundIDManager_->soundParsers_[0] = nullptr;
    EXPECT_EQ(MSERR_INVALID, soundIDManager_->Load(testUrl));
}
}  // namespace Media
}  // namespace OHOS
