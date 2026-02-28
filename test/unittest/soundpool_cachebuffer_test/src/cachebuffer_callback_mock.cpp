/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cachebuffer_callback_mock.h"

namespace OHOS {
namespace Media {
namespace {
}
/**
 * @brief Register listens for load result event.
 *
 * @param result used to listen for loaded soundId event
 * @since 1.0
 * @version 1.0
 */
void AudioStreamCallbackMock::OnLoadCompleted(int32_t soundId)
{
    loadCompletedSoundId = soundId;
    MEDIA_LOGI("AudioStreamCallbackMock::OnLoadCompleted called, soundId = %{public}d", soundId);
}

/**
 * @brief Register the play finish event to listen for.
 *
 * @since 1.0
 * @version 1.0
 */
void AudioStreamCallbackMock::OnPlayFinished(int32_t streamID)
{
    playFinishedStreamID = streamID;
    MEDIA_LOGI("AudioStreamCallbackMock::OnPlayFinished called, streamID = %{public}d", streamID);
}
/**
 * @brief Register listens for sound play error events.
 *
 * @param errorCode Type of the sound play error event to listen for.
 * @since 1.0
 * @version 1.0
 */
void AudioStreamCallbackMock::OnError(int32_t errorCode)
{
    errorErrorCode = errorCode;
    MEDIA_LOGI("AudioStreamCallbackMock::OnError called, errorCode = %{public}d", errorCode);
}

/**
 * @brief Register listens for sound play error events.
 *
 * @param errorInfo errorInfo
 * @since 1.0
 * @version 1.0
 */
void AudioStreamCallbackMock::OnErrorOccurred(Format &errorInfo)
{
    MEDIA_LOGI("AudioStreamCallbackMock::OnErrorOccurred called");
}

/**
 * @brief For test get the loadCompletedSoundId to check if callback has been called.
 *
 * @since 1.0
 * @version 1.0
 **/
int32_t AudioStreamCallbackMock::GetLoadCompletedSoundId()
{
    return loadCompletedSoundId;
}

/**
 * @brief For test get the playFinishedStreamID to check if callback has been called.
 *
 * @since 1.0
 * @version 1.0
 **/
int32_t AudioStreamCallbackMock::GetPlayFinishedStreamID()
{
    return playFinishedStreamID;
}

/**
 * @brief For test get the errorErrorCode to check if callback has been called.
 *
 * @since 1.0
 * @version 1.0
 **/
int32_t AudioStreamCallbackMock::GetErrorErrorCode()
{
    return errorErrorCode;
}
}
}
