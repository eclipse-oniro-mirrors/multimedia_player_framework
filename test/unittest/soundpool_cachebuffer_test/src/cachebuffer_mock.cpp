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

bool AudioStreamMock::CreateAudioStream(const Format &trackFormat, int32_t soundID, int32_t streamID,
    std::shared_ptr<ThreadPool> audioStreamStopThreadPool)
{
    if (audioStream_ != nullptr) {
        audioStream_.reset();
    }
    audioStream_ = std::make_shared<AudioStream>(trackFormat, soundID, streamID, audioStreamStopThreadPool);
    return audioStream_ == nullptr;
}

bool AudioStreamMock::IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(audioStream_ != nullptr, MSERR_INVALID_OPERATION, "audioStream_ == nullptr");
    return audioStream_->IsAudioRendererCanMix(audioRendererInfo);
}

int32_t AudioStreamMock::CreateAudioRenderer(const int32_t streamID,
    const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(audioStream_ != nullptr, MSERR_INVALID_OPERATION, "audioStream_ == nullptr");
    return audioStream_->CreateAudioRenderer(audioRendererInfo, playParams) == nullptr;
}

size_t AudioStreamMock::GetFileSize(const std::string& fileName)
{
    size_t fileSize = 0;
    if (!fileName.empty()) {
        struct stat fileStatus {};
        if (stat(fileName.c_str(), &fileStatus) == 0) {
            fileSize = static_cast<size_t>(fileStatus.st_size);
        }
    }
    return fileSize;
}