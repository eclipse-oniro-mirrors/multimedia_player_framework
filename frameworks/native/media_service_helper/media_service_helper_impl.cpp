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

#include "media_service_helper_impl.h"
#include "media_log.h"
#include "i_media_service.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "MediaServiceHelperImpl"};
}
namespace OHOS {
namespace Media {
std::shared_ptr<MediaServiceHelper> MediaServiceHelperFactory::CreateMediaServiceHelper()
{
    std::shared_ptr<MediaServiceHelperImpl> impl = std::make_shared<MediaServiceHelperImpl>();
    CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to new MediaServiceHelperImpl");
    return impl;
}

MediaServiceHelperImpl::MediaServiceHelperImpl()
{
    MEDIA_LOGD("MediaServiceHelperImpl:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaServiceHelperImpl::~MediaServiceHelperImpl()
{
    MEDIA_LOGD("MediaServiceHelperImpl:0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

bool MediaServiceHelperImpl::CanKillMediaService()
{
    bool canKill = MediaServiceFactory::GetInstance().CanKillMediaService();
    MEDIA_LOGD("isOnlyAVPlayerStub = %{public}s", canKill ? "true" : "false");
    return canKill;
}

} // namespace Media
} // namespace OHOS