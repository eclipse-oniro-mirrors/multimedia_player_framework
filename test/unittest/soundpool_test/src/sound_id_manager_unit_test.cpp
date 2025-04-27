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

#include "sound_id_manager_unit_test.h"
#include "media_errors.h"
#include "sound_id_manager.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

const int32_t MAX_STREAMS = 3;
const int32_t BEGIN_NUM = 0;
const int32_t STREAM_ID_BEGIN = 1;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundIdManagerUnitTest"};
}

namespace OHOS {
namespace Media {
void SoundIDManagerUnitTest::SetUpTestCase(void)
{}

void SoundIDManagerUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1);  // let PlayEngine safe exit.
}

void SoundIDManagerUnitTest::SetUp(void)
{
    AudioStandard::AudioRendererInfo audioRenderInfo;
    audioRenderInfo.contentType = AudioStandard::CONTENT_TYPE_MUSIC;
    audioRenderInfo.streamUsage = AudioStandard::STREAM_USAGE_MUSIC;
    audioRenderInfo.rendererFlags = 0;
    soundIDManager_ = std::make_shared<SoundIDManager>();
}

void SoundIDManagerUnitTest::TearDown(void)
{
    if (soundIDManager_ != nullptr) {
        soundIDManager_.reset();
    }
}

/**
 * @tc.name: soundId_function_001
 * @tc.desc: function test MulInitThreadPool
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_001, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_001 before");
    soundIDManager_->isParsingThreadPoolStarted_.store(true);
    EXPECT_EQ(MSERR_OK, soundIDManager_->InitThreadPool());
    MEDIA_LOGI("soundId_function_001 after");
}

/**
 * @tc.name: soundId_function_002
 * @tc.desc: function test DoLoad & Unload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundIDManagerUnitTest, soundId_function_002, TestSize.Level2)
{
    MEDIA_LOGI("soundId_function_002 before");
    soundIDManager_->isParsingThreadPoolStarted_.store(false);
    EXPECT_EQ(MSERR_OK, soundIDManager_->DoLoad(0));
    soundIDManager_->soundParsers_.emplace(0, nullptr);
    EXPECT_EQ(MSERR_INVALID_VAL, soundIDManager_->Unload(1));
    EXPECT_EQ(MSERR_OK, soundIDManager_->Unload(0));

    MEDIA_LOGI("soundId_function_002 after");
}

}  // namespace Media
}  // namespace OHOS