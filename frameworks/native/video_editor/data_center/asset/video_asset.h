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
#ifndef OH_VEF_ASSET_VIDEO_H
#define OH_VEF_ASSET_VIDEO_H

#include <shared_mutex>
#include "asset.h"
#include "data_center/effect/effect.h"

namespace OHOS {
namespace Media {

class VideoAsset : public Asset {
public:
    VideoAsset(int64_t id, int fd);
    ~VideoAsset() override;

    std::vector<const std::shared_ptr<Effect>> GetEffectList() const;
    void ApplyEffect(const std::shared_ptr<Effect>& effect);

private:
    mutable std::shared_mutex dataLock_;
    std::vector<std::shared_ptr<Effect>> effectList_;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_ASSET_VIDEO_H