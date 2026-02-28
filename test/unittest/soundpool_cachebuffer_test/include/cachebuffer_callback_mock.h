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
#ifndef AUDIO_STREAM_CALLBACK_MOCK_H
#define AUDIO_STREAM_CALLBACK_MOCK_H

#include "isoundpool.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "AudioStreamCallbackMock"};
}

class AudioStreamCallbackMock : public ISoundPoolCallback {
public:
    AudioStreamCallbackMock() = default;
    ~AudioStreamCallbackMock() = default;

    /**
     * @brief Register listens for load result event.
     *
     * @param result used to listen for loaded soundId event
     * @since 1.0
     * @version 1.0
     */
    void OnLoadCompleted(int32_t soundId) override;

    /**
     * @brief Register the play finish event to listen for.
     *
     * @since 1.0
     * @version 1.0
     */
    void OnPlayFinished(int32_t streamID) override;

    /**
     * @brief Register listens for sound play error events.
     *
     * @param errorCode Type of the sound play error event to listen for.
     * @since 1.0
     * @version 1.0
     */
    void OnError(int32_t errorCode) override;

    /**
     * @brief Register listens for sound play error events.
     *
     * @param errorInfo errorInfo
     * @since 1.0
     * @version 1.0
     */
    void OnErrorOccurred(Format &errorInfo) override;

    /**
     * @brief For test get the loadCompletedSoundId to check if callback has been called.
     *
     * @since 1.0
     * @version 1.0
     **/
    int32_t GetLoadCompletedSoundId();

    /**
     * @brief For test get the playFinishedStreamID to check if callback has been called.
     *
     * @since 1.0
     * @version 1.0
     **/
    int32_t GetPlayFinishedStreamID();

    /**
     * @brief For test get the errorErrorCode to check if callback has been called.
     *
     * @since 1.0
     * @version 1.0
     **/
    int32_t GetErrorErrorCode();

private:
    int32_t loadCompletedSoundId = -1;
    int32_t playFinishedStreamID = -1;
    int32_t errorErrorCode = -1;
};
}
}

#endif
