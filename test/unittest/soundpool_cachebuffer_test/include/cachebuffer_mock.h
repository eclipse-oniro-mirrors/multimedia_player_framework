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
#ifndef CACHEBUFFER_MOCK_H
#define CACHEBUFFER_MOCK_H
 
#include <fcntl.h>
#include <cstdio>
#include <mutex>
#include <cstdlib>
#include <thread>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <iostream>
#include "gtest/gtest.h"
#include "unittest_log.h"
#include "media_errors.h"
#include "nocopyable.h"
#include "cache_buffer.h"
#include "thread_pool.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace AudioStandard;
using namespace MediaAVCodec;
class CacheBufferMock {
public:
    CacheBufferMock() = default;
    ~CacheBufferMock() = default;
    bool CreateCacheBuffer(const Format &trackFormat, const int32_t &soundID, const int32_t &streamID,
        std::shared_ptr<ThreadPool> cacheBufferStopThreadPool);
    bool IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo);
    int32_t CreateAudioRenderer(const int32_t streamID,
        const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams);
private:
    std::shared_ptr<CacheBuffer> cacheBuffer_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif