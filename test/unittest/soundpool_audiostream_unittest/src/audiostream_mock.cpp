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
#include <cstring>

#include "audiostream_mock.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Media {
static constexpr size_t MAX_FILE_PATH_LEN = 1024;

/**
 * @brief Register listens for load result event.
 *
 * @param result used to listen for loaded soundId event
 * @since 1.0
 * @version 1.0
 */
void SoundPoolCallbackMock::OnLoadCompleted(int32_t soundId)
{
    loadCompletedWithSoundId = soundId;
    MEDIA_LOGI("SoundPoolCallbackMock::OnLoadCompleted called, soundId = %{public}d", soundId);
}

/**
 * @brief Register the play finish event to listen for.
 *
 * @since 1.0
 * @version 1.0
 */
void SoundPoolCallbackMock::OnPlayFinished(int32_t streamID)
{
    playFinishedWithStreamID = streamID;
    MEDIA_LOGI("SoundPoolCallbackMock::OnPlayFinished called, streamID = %{public}d", streamID);
}

/**
 * @brief Register listens for sound play error events.
 *
 * @param errorCode Type of the sound play error event to listen for.
 * @since 1.0
 * @version 1.0
 */
void SoundPoolCallbackMock::OnError(int32_t errorCode)
{
    errorCodeValue = errorCode;
    MEDIA_LOGI("SoundPoolCallbackMock::OnError called, errorCode = %{public}d", errorCode);
}

/**
 * @brief Register listens for sound play error events.
 *
 * @param errorInfo errorInfo
 * @since 1.0
 * @version 1.0
 */
void SoundPoolCallbackMock::OnErrorOccurred(Format &errorInfo)
{
    MEDIA_LOGI("SoundPoolCallbackMock::OnErrorOccurred called");
}

/**
 * @brief For test get the loadCompletedSoundId to check if callback has been called.
 *
 * @since 1.0
 * @version 1.0
 **/
int32_t SoundPoolCallbackMock::GetLoadCompletedSoundId()
{
    return loadCompletedWithSoundId;
}

/**
 * @brief For test get the playFinishedStreamID to check if callback has been called.
 *
 * @since 1.0
 * @version 1.0
 **/
int32_t SoundPoolCallbackMock::GetPlayFinishedStreamID()
{
    return playFinishedWithStreamID;
}

/**
 * @brief For test get the errorCodeValue to check if callback has been called.
 *
 * @since 1.0
 * @version 1.0
 **/
int32_t SoundPoolCallbackMock::GetErrorErrorCode()
{
    return errorCodeValue;
}

bool SoundPoolAudioStreamMock::CreateAudioStream(
    const Format &trackFormat, int32_t soundID, int32_t streamID,
    std::shared_ptr<ThreadPool> audioStreamStopThreadPool)
{
    DestroyMock();

    audioStream_ = std::make_shared<AudioStream>(trackFormat, soundID, streamID,
        audioStreamStopThreadPool);
    return audioStream_ == nullptr;
}

bool SoundPoolAudioStreamMock::IsAudioRendererCanMix(
    const AudioStandard::AudioRendererInfo &audioRendererInfo)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(
        audioStream_, MSERR_INVALID_OPERATION, "audioStream_ == nullptr");
    return audioStream_->IsAudioRendererCanMix(audioRendererInfo);
}

void SoundPoolAudioStreamMock::DestroyMock() {
    if (audio_stream_) {
        audio_stream_.reset();
    }
}

int32_t SoundPoolAudioStreamMock::CreateAudioRenderer(const int32_t streamID,
    const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams)
{
    UNITTEST_CHECK_AND_RETURN_RET_LOG(audioStream_ != nullptr, MSERR_INVALID_OPERATION, "audioStream_ == nullptr");
    return audioStream_->CreateAudioRenderer(audioRendererInfo, playParams) == nullptr;
}

size_t SoundPoolAudioStreamMock::GetFileSizeByName(const char *fileName)
{
    size_t fileSize = 0;
    if (fileName) {
        size_t filePathLen = strnlen(fileName, MAX_FILE_PATH_LEN);
        if (filePathLen > 0) {
            struct stat fileStatus {};
            if (stat(fileName, &fileStatus) == 0) {
                fileSize = static_cast<size_t>(fileStatus.st_size);
            }
        }
    }
    return fileSize;
}
} // namespace Media
} // namespace OHOS