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

#include "tone_attrs_taihe.h"

#include "system_sound_log.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "common_taihe.h"
#include "ipc_skeleton.h"
#include "ringtone_common_taihe.h"
#include "tokenid_kit.h"

using OHOS::Security::AccessToken::AccessTokenKit;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "ToneAttrsTaihe"};
}

namespace ANI::Media {
ToneAttrsImpl::ToneAttrsImpl() : toneAttrs_(nullptr) {};
ToneAttrsImpl::ToneAttrsImpl(std::shared_ptr<OHOS::Media::ToneAttrs>& nativeToneAttrs)
{
    toneAttrs_ = std::move(nativeToneAttrs);
}

static bool CheckInputString(::taihe::string_view &input)
{
    if (input.empty()) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        return false;
    }
    return true;
}

int64_t ToneAttrsImpl::GetImplPtr()
{
    return reinterpret_cast<int64_t>(this);
}

std::shared_ptr<OHOS::Media::ToneAttrs> ToneAttrsImpl::GetToneAttrs()
{
    return toneAttrs_;
}

bool ToneAttrsImpl::VerifySelfSystemPermission()
{
    OHOS::Security::AccessToken::FullTokenID selfTokenID = OHOS::IPCSkeleton::GetSelfTokenID();
    auto tokenTypeFlag =
        OHOS::Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(static_cast<uint32_t>(selfTokenID));
    if (tokenTypeFlag == OHOS::Security::AccessToken::TOKEN_NATIVE ||
        tokenTypeFlag == OHOS::Security::AccessToken::TOKEN_SHELL ||
        OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfTokenID)) {
        return true;
    }
    return false;
}

bool ToneAttrsImpl::CheckPermission()
{
    if (!VerifySelfSystemPermission()) {
        CommonTaihe::ThrowError(TAIHE_ERR_PERMISSION_DENIED, TAIHE_ERR_PERMISSION_DENIED_INFO);
        return false;
    }
    return true;
}

bool ToneAttrsImpl::CheckNativeToneAttrs()
{
    if (toneAttrs_ == nullptr) {
        taihe::set_error("toneAttrs_ is nullptr");
        return false;
    }
    return true;
}

::taihe::string ToneAttrsImpl::GetTitle()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneAttrs(), "", "toneAttrs_ is nullptr");

    return toneAttrs_->GetTitle();
}

void ToneAttrsImpl::SetTitle(::taihe::string_view title)
{
    CHECK_AND_RETURN_LOG(CheckPermission(), "No system permission");
    CHECK_AND_RETURN_LOG(CheckInputString(title), "invalid arguments");
    CHECK_AND_RETURN_LOG(CheckNativeToneAttrs(), "toneAttrs_ is nullptr");
    toneAttrs_->SetTitle(std::string(title));
}

::taihe::string ToneAttrsImpl::GetFileName()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneAttrs(), "", "toneAttrs_ is nullptr");

    return toneAttrs_->GetFileName();
}

void ToneAttrsImpl::SetFileName(::taihe::string_view name)
{
    CHECK_AND_RETURN_LOG(CheckPermission(), "No system permission");
    CHECK_AND_RETURN_LOG(CheckInputString(name), "invalid arguments");
    CHECK_AND_RETURN_LOG(CheckNativeToneAttrs(), "toneAttrs_ is nullptr");
    toneAttrs_->SetFileName(std::string(name));
}

::taihe::string ToneAttrsImpl::GetUri()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), "", "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneAttrs(), "", "toneAttrs_ is nullptr");

    return toneAttrs_->GetUri();
}

::ohos::multimedia::systemSoundManager::ToneCustomizedType ToneAttrsImpl::GetCustomizedType()
{
    ::ohos::multimedia::systemSoundManager::ToneCustomizedType result =
        ::ohos::multimedia::systemSoundManager::ToneCustomizedType::from_value(0);
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), result, "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneAttrs(), result, "toneAttrs_ is nullptr");

    return ::ohos::multimedia::systemSoundManager::ToneCustomizedType::from_value(toneAttrs_->GetCustomizedType());
}

void ToneAttrsImpl::SetCategory(int64_t category)
{
    CHECK_AND_RETURN_LOG(CheckPermission(), "No system permission");

    bool isCategoryValid = false;
    if (category == OHOS::Media::TONE_CATEGORY_RINGTONE || category == OHOS::Media::TONE_CATEGORY_TEXT_MESSAGE ||
        category == OHOS::Media::TONE_CATEGORY_NOTIFICATION || category == OHOS::Media::TONE_CATEGORY_ALARM ||
        category == OHOS::Media::TONE_CATEGORY_CONTACTS) {
        isCategoryValid = true;
    }
    if (!isCategoryValid) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        MEDIA_LOGE("invalid arguments");
        return;
    }
    CHECK_AND_RETURN_LOG(CheckNativeToneAttrs(), "toneAttrs_ is nullptr");

    toneAttrs_->SetCategory(category);
}

int64_t ToneAttrsImpl::GetCategory()
{
    CHECK_AND_RETURN_RET_LOG(CheckPermission(), 0, "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneAttrs(), 0, "toneAttrs_ is nullptr");

    return toneAttrs_->GetCategory();
}

void ToneAttrsImpl::SetMediaType(::ohos::multimedia::systemSoundManager::MediaType type)
{
    CHECK_AND_RETURN_LOG(CheckPermission(), "No system permission");

    bool isMediaTypeValid = false;
    int32_t toneAttrsMediaType = type.get_value();
    if (toneAttrsMediaType == static_cast<int32_t>(OHOS::Media::ToneMediaType::MEDIA_TYPE_AUD) ||
        toneAttrsMediaType == static_cast<int32_t>(OHOS::Media::ToneMediaType::MEDIA_TYPE_VID)) {
        isMediaTypeValid = true;
    }
    if (!isMediaTypeValid) {
        CommonTaihe::ThrowError(TAIHE_ERR_INPUT_INVALID, TAIHE_ERR_INPUT_INVALID_INFO);
        MEDIA_LOGE("invalid arguments");
        return;
    }
    CHECK_AND_RETURN_LOG(CheckNativeToneAttrs(), "toneAttrs_ is nullptr");

    toneAttrs_->SetMediaType(static_cast<OHOS::Media::ToneMediaType>(type.get_value()));
}

::ohos::multimedia::systemSoundManager::MediaType ToneAttrsImpl::GetMediaType()
{
    ::ohos::multimedia::systemSoundManager::MediaType result =
    ::ohos::multimedia::systemSoundManager::MediaType::from_value(0);

    CHECK_AND_RETURN_RET_LOG(CheckPermission(), result, "No system permission");
    CHECK_AND_RETURN_RET_LOG(CheckNativeToneAttrs(), result, "toneAttrs_ is nullptr");

    return ::ohos::multimedia::systemSoundManager::MediaType::from_value(
        static_cast<int32_t>(toneAttrs_->GetMediaType()));
}

} // namespace ANI::Media