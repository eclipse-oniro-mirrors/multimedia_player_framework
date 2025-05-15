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

#include "sound_parser_unit_test.h"
#include "media_errors.h"
#include "sound_parser.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;

const int32_t MAX_STREAMS = 3;
const int32_t BEGIN_NUM = 0;
const int32_t STREAM_ID_BEGIN = 1;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundParseUnitTest"};
}

namespace OHOS {
namespace Media {
void SoundParseUnitTest::SetUpTestCase(void)
{}

void SoundParseUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1);  // let PlayEngine safe exit.
}

void SoundParseUnitTest::SetUp(void)
{
    soundParser_ = std::make_shared<SoundParser>();
}

void SoundParseUnitTest::TearDown(void)
{
    if (soundParser_ != nullptr) {
        soundParser_.reset();
    }
}

/**
 * @tc.name: doparse failed
 * @tc.desc: function test DoParser
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoundParseUnitTest, doParser_function_001, TestSize.Level2)
{
    MEDIA_LOGI("doParser_function_001 before");
    soundParser_->source_ = std::make_shared<MediaAVCodec::AVSource>();
    soundParser_->demuxer_ = std::make_shared<MediaAVCodec::AVDemuxer>();
    soundParser_->trackFormat_ = nullptr;
    soundParser_->callback_ = std::make_shared<ISoundPoolCallback>();
    EXPECT_EQ(MSERR_INVALID_VAL, soundParser_->DoParse());
    MEDIA_LOGI("doParser_function_001 after");
}

}  // namespace Media
}  // namespace OHOS