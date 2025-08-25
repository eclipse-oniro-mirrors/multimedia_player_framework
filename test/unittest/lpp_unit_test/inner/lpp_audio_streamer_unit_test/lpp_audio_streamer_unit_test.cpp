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

#include <gtest/gtest.h>
#include <vector>
#include "lpp_audio_streamer_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void AudioStreamerUnitTest::SetUpTestCase(void)
{}

void AudioStreamerUnitTest::TearDownTestCase(void)
{}

void AudioStreamerUnitTest::SetUp(void)
{}

void AudioStreamerUnitTest::TearDown(void)
{}

/**
 * @tc.name  : AudioCreateByMime
 * @tc.number: AudioCreateByMime
 * @tc.desc  : FUNC
 */
HWTEST_F(AudioStreamerUnitTest, AudioCreateByMime_001, TestSize.Level1)
{
    std::string invalidMime = "video/avc";
    std::shared_ptr<AudioStreamer> invalidAudioPlayer = AudioStreamerFactory::CreateByMime(invalidMime);
    EXPECT_EQ(invalidAudioPlayer, nullptr);

    std::string validMime = "audio/mp4a-latm";
    std::shared_ptr<AudioStreamer> validAudioPlayer = AudioStreamerFactory::CreateByMime(validMime);
    EXPECT_NE(validAudioPlayer, nullptr);
}
}  // namespace Media
}  // namespace OHOS