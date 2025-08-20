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
#include "lpp_vedio_dec_callback_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
void LppVideoDecCallbackUnitTest::SetUpTestCase(void)
{
}

void LppVideoDecCallbackUnitTest::TearDownTestCase(void)
{
}

void LppVideoDecCallbackUnitTest::SetUp(void)
{
    videoDecAdapter_ = std::make_shared<LppVideoDecoderAdapter>(streamerId_, isLpp_);
    callback_ = std::make_shared<LppVideoDecoderCallback>(videoDecAdapter_);
}

void LppVideoDecCallbackUnitTest::TearDown(void)
{
    videoDecAdapter_ = nullptr;
    callback_ = nullptr;
}

/**
* @tc.name    : Test OnError API
* @tc.number  : onError_001
* @tc.desc    : Test OnError interface in normal case
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecCallbackUnitTest, onError_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, callback_);
    MediaAVCodec::AVCodecErrorType errorType = MediaAVCodec::AVCodecErrorType::AVCODEC_ERROR_FRAMEAORK_FAILED;
    int32_t errorCode = 1001;

    callback_->OnError(errorType, errorCode);
}

/**
* @tc.name    : Test OnOutputFormatChanged API
* @tc.number  : OnOutputFormatChanged_001
* @tc.desc    : Test OnOutputFormatChanged interface in normal case
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecCallbackUnitTest, OnOutputFormatChanged_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, callback_);
    MediaAVCodec::Format format;

    callback_->OnOutputFormatChanged(format);
}

/**
* @tc.name    : Test OnInputBufferAvailable API
* @tc.number  : OnInputBufferAvailable_001
* @tc.desc    : Test OnInputBufferAvailable interface in normal case
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecCallbackUnitTest, OnInputBufferAvailable_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, callback_);
    
    auto buffer = std::make_shared<AVBuffer>();

    callback_->OnInputBufferAvailable(0, buffer);
}

/**
* @tc.name    : Test OnOutputBufferAvailable API
* @tc.number  : OnOutputBufferAvailable_001
* @tc.desc    : Test OnOutputBufferAvailable interface in normal case
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecCallbackUnitTest, OnOutputBufferAvailable_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, callback_);
    auto buffer = std::make_shared<AVBuffer>();

    callback_->OnOutputBufferAvailable(0, buffer);
}

/**
* @tc.name    : Test OnOutputBufferBinded API
* @tc.number  : OnOutputBufferBinded_001
* @tc.desc    : Test OnOutputBufferBinded interface in normal case
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecCallbackUnitTest, OnOutputBufferBinded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, callback_);
    std::map<uint32_t, sptr<SurfaceBuffer>> bufferMap = {};

    callback_->OnOutputBufferBinded(bufferMap);
}

/**
* @tc.name    : Test OnOutputBufferUnbinded API
* @tc.number  : OnOutputBufferUnbinded_001
* @tc.desc    : Test OnOutputBufferUnbinded interface in normal case
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppVideoDecCallbackUnitTest, OnOutputBufferUnbinded_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, videoDecAdapter_);
    ASSERT_NE(nullptr, callback_);

    callback_->OnOutputBufferUnbinded();
}

} // namespace Media
} // namespace OHOS