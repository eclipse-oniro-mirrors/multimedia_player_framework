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

#ifndef LPP_VIDEO_STREAMER_SERVICE_PROXY_H
#define LPP_VIDEO_STREAMER_SERVICE_PROXY_H

#include "i_standard_lpp_video_streamer_service.h"
#include "media_parcel.h"

namespace OHOS {
namespace Media {
class LppVideoStreamerServiceProxy : public IRemoteProxy<IStandardLppVideoStreamerService> {
public:
    explicit LppVideoStreamerServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~LppVideoStreamerServiceProxy();

    int32_t Init(const std::string &mime) override;

    int32_t SetParameter(const Format &param) override;

    int32_t GetParameter(Format &param) override;

    int32_t Configure(const Format &param) override;
    
    int32_t Prepare() override;

    int32_t Start() override;

    int32_t Pause() override;

    int32_t Resume() override;

    int32_t Flush() override;

    int32_t Stop() override;

    int32_t Reset() override;

    int32_t Release() override;

    int32_t StartDecode() override;

    int32_t StartRender() override;

    int32_t SetOutputSurface(sptr<Surface> surface) override;

    int32_t SetSyncAudioStreamer(AudioStreamer *audioStreamer) override;
    
    int32_t SetTargetStartFrame(const int64_t targetPts, const int timeoutMs) override;

    int32_t SetVolume(float volume) override;

    int32_t SetPlaybackSpeed(float speed) override;

    int32_t ReturnFrames(sptr<LppDataPacket> framePacket) override;

    int32_t RegisterCallback() override;

    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;
    
    int32_t SetLppVideoStreamerCallback() override;

    int32_t SetLppAudioStreamerId(const std::string audioStreamId) override;

    std::string GetStreamerId() override;

    int32_t GetLatestPts(int64_t &pts) override;

    int32_t RenderFirstFrame() override;
private:
    static inline BrokerDelegator<LppVideoStreamerServiceProxy> delegator_;
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_SERVICE_PROXY_H
