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
#include "data_center/asset/asset.h"

namespace OHOS {
namespace Media {

Asset::Asset(int64_t id, AssetType type, int fd) : id_(id), type_(type), fd_(fd) {}

uint64_t Asset::GetId() const
{
    return id_;
}

int Asset::GetFd() const
{
    return fd_;
}

AssetType Asset::GetType() const
{
    return type_;
}

} // namespace Media
} // namespace OHOS
