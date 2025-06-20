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

#ifndef RING_TONE_ACCESS_TOKEN_H
#define RING_TONE_ACCESS_TOKEN_H

#include "accesstoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Media {
using namespace Security::AccessToken;
using Security::AccessToken::AccessTokenID;

inline HapInfoParams testInfoParams = {
    .bundleName = "test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "test",
    //.apiVersion = 8,
    .isSystemApp = true,
};

inline PermissionStateFull testPlaceCallState = {
    .permissionName = "ohos.permission.WRITE_RINGTONE",
    .isGeneral = true,
    .resDeviceID = { "local" },
    .grantStatus = { PermissionState::PERMISSION_GRANTED },
    .grantFlags = { 1 }, // PERMISSION_USER_SET
};

inline HapPolicyParams testPolicyParams = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test",
    .permList = {},
    .permStateList = { testPlaceCallState },
};

class AccessToken {
public:
    AccessToken()
    {
        currentID_ = GetSelfTokenID();
        AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(testInfoParams, testPolicyParams);
        accessID_ = tokenIdEx.tokenIdExStruct.tokenID;
        SetSelfTokenID(tokenIdEx.tokenIDEx);
    }
    ~AccessToken()
    {
        AccessTokenKit::DeleteToken(accessID_);
        SetSelfTokenID(currentID_);
    }
private:
    AccessTokenID currentID_ = 0;
    AccessTokenID accessID_ = 0;
};
} // namespace Media
} // namespace OHOS

#endif //RING_TONE_ACCESS_TOKEN_H