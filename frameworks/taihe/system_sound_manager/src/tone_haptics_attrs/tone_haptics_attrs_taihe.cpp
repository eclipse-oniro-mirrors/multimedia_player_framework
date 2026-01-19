/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "tone_haptics_attrs_taihe.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "common_taihe.h"
#include "ipc_skeleton.h"
#include "ringtone_common_taihe.h"
#include "system_sound_log.h"
#include "tokenid_kit.h"

using OHOS::Security::AccessToken::AccessTokenKit;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "ToneHapticsAttrsTaihe"};
}

namespace ANI::Media {
ToneHapticsAttrsImpl::ToneHapticsAttrsImpl() : toneHapticsAttrs_(nullptr) {};
ToneHapticsAttrsImpl::ToneHapticsAttrsImpl(std::shared_ptr<OHOS::Media::ToneHapticsAttrs> &nativeToneHapticsAttrs)
{
    toneHapticsAttrs_ = std::move(nativeToneHapticsAttrs);
}

bool ToneHapticsAttrsImpl::CheckPermission()
{
    if (!CommonTaihe::VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return false;
    }
    return true;
}

bool ToneHapticsAttrsImpl::CheckNativeToneHapticsAttrs()
{
    if (toneHapticsAttrs_ == nullptr) {
        CommonTaihe::ThrowError("toneHapticsAttrs_ is nullptr");
        return false;
    }
    return true;
}

::taihe::string ToneHapticsAttrsImpl::GetUri()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneHapticsAttrs(), "", "toneHapticsAttrs_ is nullptr");

    return toneHapticsAttrs_->GetUri();
}

::taihe::string ToneHapticsAttrsImpl::GetTitle()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneHapticsAttrs(), "", "toneHapticsAttrs_ is nullptr");

    return toneHapticsAttrs_->GetTitle();
}

::taihe::string ToneHapticsAttrsImpl::GetFileName()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneHapticsAttrs(), "", "toneHapticsAttrs_ is nullptr");

    return toneHapticsAttrs_->GetFileName();
}

::taihe::string ToneHapticsAttrsImpl::GetGentleUri()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneHapticsAttrs(), "", "toneHapticsAttrs_ is nullptr");

    return toneHapticsAttrs_->GetGentleUri();
}

::taihe::string ToneHapticsAttrsImpl::GetGentleTitle()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneHapticsAttrs(), "", "toneHapticsAttrs_ is nullptr");

    return toneHapticsAttrs_->GetGentleTitle();
}

::taihe::string ToneHapticsAttrsImpl::GetGentleFileName()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneHapticsAttrs(), "", "toneHapticsAttrs_ is nullptr");

    return toneHapticsAttrs_->GetGentleFileName();
}
} // namespace ANI::Media