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

#ifndef PCM_OUTPUT_CALLBACK_PROXY_H
#define PCM_OUTPUT_CALLBACK_PROXY_H

#include "i_standard_pcm_output_callback.h"
#include "iremote_proxy.h"
#include "dolby_passthrough.h"

namespace OHOS {
namespace Media {
class PCMCallback : public IPCMCallback, public NoCopyable {
public:
    explicit PCMCallback(const sptr<IStandardPCMOutputCallback> &ipcProxy);
    virtual ~PCMCallback();

    void OnPCMOutput(const std::shared_ptr<AVBuffer> &buffer) override;
    void OnPCMProcessor(const std::shared_ptr<AVBuffer> &buffer) override;

private:
    sptr<IStandardPCMOutputCallback> callbackProxy_ = nullptr;
};

class PCMOutputCallbackProxy : public IRemoteProxy<IStandardPCMOutputCallback>, public NoCopyable {
public:
    explicit PCMOutputCallbackProxy(const sptr<IRemoteObject> &impl);
    virtual ~PCMOutputCallbackProxy() = default;

    void OnPCMOutput(const std::shared_ptr<AVBuffer> &buffer) override;
    void OnPCMProcessor(const std::shared_ptr<AVBuffer> &buffer) override;

private:
    static inline BrokerDelegator<PCMOutputCallbackProxy> delegator_;
};
} // namespace Media
} // namespace OHOS
#endif // PCM_OUTPUT_CALLBACK_PROXY_H
