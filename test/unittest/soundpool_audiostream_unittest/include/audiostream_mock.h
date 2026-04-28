/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifndef AUDIOSTREAM_MOCK_H
#define AUDIOSTREAM_MOCK_H

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
#include "isoundpool.h"
#include "media_errors.h"
#include "nocopyable.h"
#include "thread_pool.h"
#include "unittest_log.h"

namespace OHOS {
namespace Media {

using namespace std;
using namespace AudioStandard;
using namespace MediaAVCodec;

class SoundPoolCallbackMock : public ISoundPoolCallback {
public:
    SoundPoolCallbackMock() = default;
    ~SoundPoolCallbackMock() = default;

    /**
     * @brief For test get the loadCompletedSoundId to check if callback has been called.
     *
     * @since 1.0
     * @version 1.0
     **/
    int32_t GetLoadCompletedSoundId();

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
    int32_t loadCompletedWithSoundId = -1;
    int32_t playFinishedWithStreamID = -1;
    int32_t errorCodeValue = -1;
};

class SoundPoolAudioStreamMock {
public:
    SoundPoolAudioStreamMock() = default;
    ~SoundPoolAudioStreamMock() = default;
    bool CreateAudioStream(const Format &trackFormat, int32_t soundID, int32_t streamID,
        std::shared_ptr<ThreadPool> audioStreamStopThreadPool);
    bool IsAudioRendererCanMix(const AudioStandard::AudioRendererInfo &audioRendererInfo);
    void DestroyMock();
    int32_t CreateAudioRenderer(const int32_t streamID,
        const AudioStandard::AudioRendererInfo audioRendererInfo, const PlayParams playParams);
    size_t GetFileSizeByName(const char *fileName);
private:
    std::shared_ptr<AudioStream> audioStream_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif