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
#include "data_center/impl/data_center_impl.h"
#include "data_center/asset/video_asset.h"
#include "data_center/asset/asset_factory.h"
#include "data_center/effect/effect_factory.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "DataCenter"};
}

constexpr uint64_t INPUT_VIDEO_COUNT_THRESHOLD = 1;   // Currently, only one input video is supported.

std::shared_ptr<IDataCenter> IDataCenter::Create()
{
    return std::make_shared<DataCenterImpl>();
}

VEFError DataCenterImpl::AppendVideo(int fileFd, const std::string& effectDescription)
{
    std::unique_lock<std::shared_mutex> lock(dataLock_);
    if (assetList_.size() >= INPUT_VIDEO_COUNT_THRESHOLD) {
        MEDIA_LOGE("create asset for video[%{public}d] failed", fileFd);
        return VEFError::ERR_INPUT_VIDEO_COUNT_LIMITED;
    }
    auto asset = AssetFactory::CreateAsset(AssetType::VIDEO, fileFd);
    if (asset == nullptr) {
        MEDIA_LOGE("create asset for video[%{public}d] failed", fileFd);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    auto effect = EffectFactory::CreateEffect(effectDescription);
    if (effect == nullptr) {
        MEDIA_LOGE("create effect[%{public}s] failed.", effectDescription.c_str());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    if (asset->GetType() != AssetType::VIDEO) {
        MEDIA_LOGE("asset[id = %{public}" PRIu64 "] is not video asset.", asset->GetId());
        return VEFError::ERR_INTERNAL_ERROR;
    }
    auto videoAsset = std::static_pointer_cast<VideoAsset>(asset);
    videoAsset->ApplyEffect(effect);
    assetList_.push_back(asset);
    MEDIA_LOGI("create asset for video[%{public}d] success.", fileFd);
    return VEFError::ERR_OK;
}

std::vector<const std::shared_ptr<Asset>> DataCenterImpl::GetAssetList() const
{
    std::shared_lock<std::shared_mutex> lock(dataLock_);
    std::vector<const std::shared_ptr<Asset>> result;
    std::copy(assetList_.begin(), assetList_.end(), std::back_inserter(result));
    return result;
}

} // namespace Media
} // namespace OHOS
