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

#ifndef OH_VEF_ASSET_BASE_H
#define OH_VEF_ASSET_BASE_H

#include "data_center/effect/effect.h"

namespace OHOS {
namespace Media {

enum class AssetType : uint32_t {
    VIDEO,
    AUDIO,
    UNKNOWN
};

constexpr int INVALID_FILE_FD = -1;

class Asset {
public:
    Asset(int64_t id, AssetType type, int fd);
    virtual ~Asset() = default;

    uint64_t GetId() const;
    int GetFd() const;
    AssetType GetType() const;

protected:
    uint64_t id_ = 0;
    AssetType type_ = AssetType::UNKNOWN;
    int fd_ = INVALID_FILE_FD;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_ASSET_BASE_H
