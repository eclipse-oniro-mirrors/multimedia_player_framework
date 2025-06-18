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

#ifndef LPP_AUDIO_STREAM_LISTENER_PROXY_H
#define LPP_AUDIO_STREAM_LISTENER_PROXY_H

#include "i_standard_lpp_video_streamer_listener.h"
#include "media_death_recipient.h"
#include "lpp_video_streamer.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
class LppVideoStreamerListenerCallback : public VideoStreamerCallback, public NoCopyable {
public:
    explicit LppVideoStreamerListenerCallback(const sptr<IStandardLppVideoStreamerListener> &listener);
    virtual ~LppVideoStreamerListenerCallback();

    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(VideoStreamerOnInfoType type, int32_t extra, const Format &infoBody = {}) override;

private:
    sptr<IStandardLppVideoStreamerListener> listener_ = nullptr;
};

class LppVideoStreamerListenerProxy : public IRemoteProxy<IStandardLppVideoStreamerListener>, public NoCopyable {
public:
    explicit LppVideoStreamerListenerProxy(const sptr<IRemoteObject> &impl);
    virtual ~LppVideoStreamerListenerProxy();

    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(VideoStreamerOnInfoType type, int32_t extra, const Format &infoBody = {}) override;

private:
    static inline BrokerDelegator<LppVideoStreamerListenerProxy> delegator_;
};
}
} // namespace OHOS
#endif // RECORDER_LISTENER_PROXY_H
