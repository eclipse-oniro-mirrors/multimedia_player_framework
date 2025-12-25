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

#ifndef DOLBY_PASSTHROUGH_PROXY_H
#define DOLBY_PASSTHROUGH_PROXY_H

#include "i_standard_dolby_passthrough.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
class DolbyPassthroughCallback :  public IDolbyPassthrough, public NoCopyable {
public:
    explicit DolbyPassthroughCallback(const sptr<IStandardDolbyPassthrough> &ipcProxy);
    virtual ~DolbyPassthroughCallback();

    bool IsAudioPass(const char* mime);
    std::vector<std::string> GetList();
    
private:
    sptr<IStandardDolbyPassthrough> callbackProxy_ = nullptr;
};

class DolbyPassthroughProxy : public IRemoteProxy<IStandardDolbyPassthrough>, public NoCopyable {
public:
    explicit DolbyPassthroughProxy(const sptr<IRemoteObject> &impl);
    virtual ~DolbyPassthroughProxy();

    bool IsAudioPass(const char* mime) override;
    std::vector<std::string> GetList() override;

private:
    static inline BrokerDelegator<DolbyPassthroughProxy> delegator_;
};
} // namespace Media
} // namespace OHOS
#endif // DOLBY_PASSTHROUGH_PROXY_H