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

#include "scoped_hap_token.h"
#include "media_log.h"

using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
namespace {
constexpr HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "ScopedHapToken" };
constexpr std::string_view TOKEN_ID_KEY = "\"tokenID\": ";

uint64_t GetFoundationTokenId()
{
    AtmToolsParamInfo info;
    info.processName = "foundation";
    std::string dumpInfo;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t tokenIdPos = dumpInfo.find(TOKEN_ID_KEY);
    if (tokenIdPos == std::string::npos) {
        return 0;
    }
    tokenIdPos += TOKEN_ID_KEY.size();
    std::string tokenIdStr = dumpInfo.substr(tokenIdPos);
    char *end = nullptr;
    uint64_t tokenId = strtoull(tokenIdStr.c_str(), &end, 10);
    return end != tokenIdStr.c_str() ? tokenId : 0;
}
} // namespace

ScopedHapToken::ScopedHapToken(const std::vector<std::string> &permissions, const std::string &bundleName)
{
    oldTokenId_ = GetSelfTokenID();
    managerTokenId_ = GetFoundationTokenId();
    if (managerTokenId_ == 0 || SetSelfTokendID(managerTokenId_) != 0) {
        MEDIA_LOGE("get or set foundation token failed");
        return;
    }

    HapInfoParams info = {
        .userID = 100,  // 100 user ID
        .bundleName = bundleName,
        .instIndex = 0,
        .appIDDesc = bundleName,
        .apiVersion = 8,
        .isSystemApp = true
    };

    std::vector<PermissionStateFull> perStateList;
    for (const auto &perm : permissions) {
        perStateList.push_back({
            .permissionName = perm,
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        });
    }

    HapPolicyParams policy = {
        .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain.avmetadata_unit_test",
        .permList = {},
        .permStateList = permStateList
    };

    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    accessTokenId_ = tokenIdEx.tokenIdExStruct.tokenID;
    isValid_ = accessTokenId_ != 0 && SetSelfTokenID(tokenIdEx.tokenIDEx) == 0 &&
        GetSelfTokenID() == tokenIdEx.tokenIDEx;
    if (!isValid_) {
        MEDIA_LOGE("alloc or set hap token failed");
    }
}

ScopedHapToken::~ScopedHapToken()
{
    if (managerTokenId_ != 0 && SetSelfTokenID(managerTokenId_) == 0 && accessTokenId_ != 0) {
        (void)AccessTokenKit::DeleteToken(accessTokenId_);
    }
    (void)SetSelfTokenID(oldTokenId_);
}

bool ScopedHapToken::IsValid() const
{
    return isValid_;
}
} // namespace Media
} // namespace OHOS
 