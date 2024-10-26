/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include "video_asset.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "DataCenter"};
}

VideoAsset::VideoAsset(int64_t id, int fd) : Asset(id, AssetType::VIDEO, fd)
{
}

VideoAsset::~VideoAsset()
{
    MEDIA_LOGD("video asset[id = %{public}" PRIu64 "] destruct.", id_);
}

std::vector<const std::shared_ptr<Effect>> VideoAsset::GetEffectList() const
{
    std::shared_lock<std::shared_mutex> lock(dataLock_);
    std::vector<const std::shared_ptr<Effect>> result;
    std::copy(effectList_.begin(), effectList_.end(), std::back_inserter(result));
    return result;
}

void VideoAsset::ApplyEffect(const std::shared_ptr<Effect>& effect)
{
    if (effect == nullptr) {
        MEDIA_LOGE("apply effect to asset[id = %{public}" PRIu64 "] failed, effect is null.", id_);
        return;
    }
    std::unique_lock<std::shared_mutex> lock(dataLock_);
    effectList_.push_back(effect);
}

} // namespace Media
} // namespace OHOS
