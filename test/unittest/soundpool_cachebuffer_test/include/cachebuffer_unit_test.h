/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CACHEBUFFER_UNIT_TEST_H
#define CACHEBUFFER_UNIT_TEST_H

#include "gtest/gtest.h"
#include "cachebuffer_mock.h"
#include "soundpool.h"
#include "soundpool_manager.h"
#include "sound_parser.h"
#include "thread_pool.h"
#include "avcodec_audio_decoder.h"
#include "avcodec_errors.h"
#include "avdemuxer.h"
#include "avsource.h"

namespace OHOS {
namespace Media {
using namespace AudioStandard;
using namespace MediaAVCodec;
class AudioStreamUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);

protected:
    static const int32_t waitTime1 = 1;
    static const int32_t waitTime2 = 2;
    static const int32_t waitTime3 = 3;
    static const int32_t waitTime10 = 10;
    static const int32_t waitTime20 = 20;
    static const int32_t waitTime30 = 30;
    int32_t loadNum_ = 0;
    void CreateAudioStream(const Format &trackFormat, const int32_t &soundID, const int32_t &streamID);
    int32_t GetFdByFileName(std::string fileName);
    std::shared_ptr<AudioStreamMock> audioStream_ = nullptr;
    std::shared_ptr<ThreadPool> audioStreamStopThreadPool_;
    std::atomic<bool> isAudioStreamStopThreadPoolStarted_ = false;
};
} // namespace Media
} // namespace OHOS
#endif