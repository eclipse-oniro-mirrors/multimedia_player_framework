/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef LPP_AUDIO_DATA_MANAGER_H
#define LPP_AUDIO_DATA_MANAGER_H

#include <queue>
#include <string>

#include "refbase.h"
#include "pipeline/pipeline.h"
#include "lpp_audio_callback_looper.h"
#include "lpp_common.h"
#include "i_lpp_sync_manager.h"
#include "osal/task/task.h"

namespace OHOS {
namespace Media {
using namespace Pipeline;

class LppAudioDataManager : public std::enable_shared_from_this<LppAudioDataManager> {
public:
    explicit LppAudioDataManager(const std::string &streamerId);
    ~LppAudioDataManager();

    void OnDataNeeded(const int32_t maxBufferSize);
    void OnDataNeededInner(const int32_t maxBufferSize);
    int32_t ProcessNewData(sptr<LppDataPacket> framePacket);
    void SetCallbackLooper(std::shared_ptr<LppAudioCallbackLooper> callbackLooper);
    int32_t Stop();
    int32_t Reset();
    int32_t Prepare();
    int32_t Start();
    int32_t Pause();
    int32_t Resume();
    int32_t Flush();
    void ProcessDataPacket();
    int32_t SetDecoderInputProducer(sptr<Media::AVBufferQueueProducer> producer);
    void OnBufferAvailable();
    void SetEventReceiver(std::shared_ptr<EventReceiver> eventReceiver);

private:
    void HandleBufferAvailable();

    std::string streamerId_{};
    std::queue<sptr<LppDataPacket>> framePackets_;

    std::mutex dataPacketMutex_{};
    bool isRequiringData_{false};
    std::unique_ptr<OHOS::Media::Task> dataTask_{nullptr};
    sptr<LppDataPacket> dataPacket_ = nullptr;
    sptr<Media::AVBufferQueueProducer> inputProducer_{nullptr};
    std::shared_ptr<EventReceiver> eventReceiver_ {nullptr};
};
}  // namespace Media
}  // namespace OHOS
#endif