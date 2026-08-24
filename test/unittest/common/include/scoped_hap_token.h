/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SCOPED_HAP_TOKEN_H
#define SCOPED_HAP_TOKEN_H

#include <memory>
#include <string>
#include <vector>
#include "accesstoken_kit.h"
#include "token_setproc.h"
#include "nativetoken_kit.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Media {

class ScopedHapToken {
public:
    explicit ScopedHapToken(const std::vector<std::string> &permissions,
        const std::string &bundleName = "com.ohos.test.mediaplayertdd");

    ~ScopedHapToken();

    bool IsValid() const;

private:
    uint64_t oldTokenId_ = 0;
    uint64_t managerTokenId_ = 0;
    Security::AccessToken::AccessTokenID accessTokenId_ = 0;
    bool valid_ = false;
};

class PlayerServer;

template<typename T>
void SyncPlayerServerToken(const std::shared_ptr<T> &player)
{
    auto server = std::static_pointer_cast<PlayerServer>(player);
    if (server != nullptr) {
        server->appTokenId_ = IPCSkeleton::GetCallingTokenID();
        server->appUid_ = IPCSkeleton::GetCallingUid();
        server->appPid_ = IPCSkeleton::GetCallingPid();
    }
}

} // namespace Media
} // namespace OHOS

#endif // SCOPED_HAP_TOKEN_H
