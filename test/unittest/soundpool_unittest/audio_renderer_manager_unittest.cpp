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

#include "media_errors.h"
#include "audio_renderer_manager_unittest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void AudioRendererManagerUnittest::SetUpTestCase(void) {}
void AudioRendererManagerUnittest::TearDownTestCase(void) {}
void AudioRendererManagerUnittest::SetUp(void) {}
void AudioRendererManagerUnittest::TearDown(void) {}

/**
 * @tc.name  : Test RemoveOldAudioRenderer
 * @tc.number: AudioRendererManagerRemoveOldAudioRenderer_001
 * @tc.desc  : Test audioRendererVector_.size() > 0
 *             Test removeGlobeId > 0
 */
HWTEST_F(AudioRendererManagerUnittest, AudioRendererManagerRemoveOldAudioRenderer_001, TestSize.Level0)
{
    AudioRendererManager& testPtr = AudioRendererManager::GetInstance();
    ASSERT_NE(&testPtr, nullptr);
    auto mockAudioRenderer = std::make_unique<MockAudioRenderer>();
    EXPECT_CALL(*(mockAudioRenderer), Release()).WillRepeatedly(Return(false));
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer = std::move(mockAudioRenderer);
    testPtr.audioRendererVector_.push_back(
        std::make_pair(1, std::move(audioRenderer))
    );
    testPtr.RemoveOldAudioRenderer();
    EXPECT_EQ(testPtr.audioRendererVector_.size(), 0);
}
} // namespace Media
} // namespace OHOS
