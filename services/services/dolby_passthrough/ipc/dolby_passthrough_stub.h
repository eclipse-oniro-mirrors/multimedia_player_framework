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

#ifndef DOLBY_PASSTHROUGH_STUB_H
#define DOLBY_PASSTHROUGH_STUB_H

#include "i_standard_dolby_passthrough.h"
#include "nocopyable.h"
#include "player.h"

namespace OHOS {
namespace Media {
class DolbyPassthroughStub : public IRemoteStub<IStandardDolbyPassthrough>, public NoCopyable {
public:
    explicit DolbyPassthroughStub(IsAudioPassthrough callback, GetDolbyList getDolbyList);
    virtual ~DolbyPassthroughStub();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    bool IsAudioPass(const char* mime) override;
    std::vector<std::string> GetList() override;

private:
    IsAudioPassthrough callback_ = nullptr;
    GetDolbyList getDolbyList_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // DOLBY_PASSTHROUGH_STUB_H