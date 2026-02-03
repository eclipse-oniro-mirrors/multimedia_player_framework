/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef AUDIO_STREAM_MOCK_H
#define AUDIO_STREAM_MOCK_H
 
#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "audio_stream.h"
#include "gtest/gtest.h"
#include "media_errors.h"
#include "nocopyable.h"
#include "thread_pool.h"
#include "unittest_log.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace AudioStandard;
using namespace MediaAVCodec;
class AudioStreamMock {
public:
    AudioStreamMock() = default;
    ~AudioStreamMock() = default;
    bool CreateAudioStream(const Format &trackFormat, int32_t soundID, int32_t streamID,
        std::shared_ptr<ThreadPool> audioStreamStopThreadPool);
    bool IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo);
    int32_t CreateAudioRenderer(const int32_t streamID,
        const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams);
    size_t GetFileSize(const std::string& fileName);
private:
    std::shared_ptr<AudioStream> audioStream_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif