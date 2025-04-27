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

#include "cachebuffer_mock.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

bool CacheBufferMock::CreateCacheBuffer(const Format &trackFormat, const int32_t &soundID,
    const int32_t &streamID, std::shared_ptr<ThreadPool> cacheBufferStopThreadPool)
{
    if (cacheBuffer_ != nullptr) {
        cacheBuffer_.reset();
    }
    cacheBuffer_ = std::make_shared<CacheBuffer>(trackFormat, soundID, streamID, cacheBufferStopThreadPool);
    return cacheBuffer_ == nullptr;
}

bool CacheBufferMock::IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(cacheBuffer_ != nullptr, MSERR_INVALID_OPERATION, "cacheBuffer_ == nullptr");
    return cacheBuffer_->IsAudioRendererCanMix(audioRendererInfo);
}

std::unique_ptr<AudioStandard::AudioRenderer> CacheBufferMock::CreateAudioRenderer(
    const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(cacheBuffer_ != nullptr, nullptr, "cacheBuffer_ == nullptr");
    return cacheBuffer_->CreateAudioRenderer(audioRendererInfo, playParams);
}