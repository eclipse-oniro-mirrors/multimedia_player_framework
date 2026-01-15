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

#ifndef LPP_VIDEO_STREAMER_LISTENER_STUB_H
#define LPP_VIDEO_STREAMER_LISTENER_STUB_H

#include "i_standard_lpp_video_streamer_listener.h"
#include "lpp_video_streamer.h"
#include "monitor_client_object.h"

namespace OHOS {
namespace Media {
class LppVideoStreamerListenerStub : public IRemoteStub<IStandardLppVideoStreamerListener> {
public:
    LppVideoStreamerListenerStub();
    virtual ~LppVideoStreamerListenerStub();
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(VideoStreamerOnInfoType type, int32_t extra, const Format &infoBody = {}) override;
    void SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback);

private:
    std::shared_ptr<VideoStreamerCallback> callback_ = nullptr;
    std::mutex vListenStubMutex_;
};
} // namespace Media
} // namespace OHOS
#endif // LPP_AUDIO_STREAM_LISTENER_STUB_H