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
#ifndef LPP_VIDEO_DATA_MANAGER_H
#define LPP_VIDEO_DATA_MANAGER_H

#include <string>

#include "refbase.h"
#include "pipeline/pipeline.h"
#include "lpp_video_callback_looper.h"
#include "lpp_common.h"
#include "lpp_vdec_adapter.h"
#include "meta/format.h"

namespace OHOS {
namespace Media {

class LppVideoDataManager : public std::enable_shared_from_this<LppVideoDataManager> {
public:
    LppVideoDataManager(const std::string &streamerId, bool isLpp);
    ~LppVideoDataManager();

    void OnDataNeeded(const int32_t maxBufferSize, const int32_t maxFrameNum);
    int32_t ProcessNewData(sptr<LppDataPacket> framePacket);

    int32_t Configure(const Format &params);
    int32_t Prepare();
    int32_t StartDecode();
    int32_t Pause();
    int32_t Resume();
    int32_t Flush();
    int32_t Stop();
    int32_t Reset();
    int32_t SetDecoderInputProducer(sptr<Media::AVBufferQueueProducer> producer);
    void OnBufferAvailable();
    void SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver);

private:
    void HandleBufferAvailable();
    void DumpBufferIfNeeded(const std::string &fileName, const std::shared_ptr<AVBuffer>& buffer);

    std::string streamerId_ {};

    std::mutex dataPacketMutex_ {};
    sptr<LppDataPacket> dataPacket_ = nullptr;
    bool isRequiringData_ {false};
    std::unique_ptr<OHOS::Media::Task> dataTask_ {nullptr};

    bool isLpp_ {true};
    bool disablePacketInput_ {false};
    sptr<Media::AVBufferQueueProducer> inputProducer_{nullptr};
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ {nullptr};
    bool dumpBufferNeeded_ {false};
    std::string dumpFileNameOutput_ {};
};
}
}
#endif