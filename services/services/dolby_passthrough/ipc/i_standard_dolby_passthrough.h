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

#ifndef I_STANDARD_DOLBY_PASSTHROUGH_H
#define I_STANDARD_DOLBY_PASSTHROUGH_H

#include "ipc_types.h" 
#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "nocopyable.h"
#include "dolby_passthrough.h"

namespace OHOS {
namespace Media {
class IStandardDolbyPassthrough : public IRemoteBroker {
public:
    virtual ~IStandardDolbyPassthrough() = default;
    virtual bool IsAudioPass(const char* mime) = 0;
    virtual std::vector<std::string> GetList() = 0;

    enum class ListenerMsg : uint8_t {
        IS_AUDIO_PASS = 0,
        GET_LIST,
    };

    DECLARE_INTERFACE_DESCRIPTOR(u"IStandardDolbyPassthrough");
};
} // namespace Media
} // namespace OHOS
#endif // I_STANDARD_DOLBY_PASSTHROUGH_H