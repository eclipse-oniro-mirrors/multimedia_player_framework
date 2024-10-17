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

#ifndef OH_VEF_DATA_CENTER_IMPL_H
#define OH_VEF_DATA_CENTER_IMPL_H

#include <memory>
#include <vector>
#include <shared_mutex>
#include "data_center/asset/asset.h"
#include "data_center/data_center.h"

namespace OHOS {
namespace Media {

class DataCenterImpl : public IDataCenter {
public:
    DataCenterImpl() = default;
    virtual ~DataCenterImpl() = default;

    VEFError AppendVideo(int fileFd, const std::string& effectDescription) override;

    std::vector<const std::shared_ptr<Asset>> GetAssetList() const override;

private:
    mutable std::shared_mutex dataLock_;
    std::vector<std::shared_ptr<Asset>> assetList_;
};

} // namespace Media
} // namespace OHOS

#endif //OH_VEF_DATA_CENTER_IMPL_H
