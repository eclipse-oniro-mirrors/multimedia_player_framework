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

#ifndef I_STANDARD_LPP_AUDIO_STREAMER_LISTENER_H
#define I_STANDARD_LPP_AUDIO_STREAMER_LISTENER_H

#include "ipc_types.h"
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "lpp_audio_streamer.h"

namespace OHOS {
namespace Media {
class IStandardLppAudioStreamerListener : public IRemoteBroker {
public:
    virtual ~IStandardLppAudioStreamerListener() = default;
    virtual void OnError(int32_t errorCode, const std::string &errorMsg) = 0;
    virtual void OnInfo(AudioStreamerOnInfoType type, int32_t extra, const Format &infoBody) = 0;

    /**
     * IPC code ID
     */
    enum LppAudioStreamerListenerMsg {
        ON_ERROR = 0,
        ON_INFO,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardLppAudioStreamerListener");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_LPP_AUDIO_STREAM_LISTENER_H
