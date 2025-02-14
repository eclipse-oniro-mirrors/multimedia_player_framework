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

#ifndef CJ_MEDIA_DATA_SOURCE_CALLBACK_H
#define CJ_MEDIA_DATA_SOURCE_CALLBACK_H

#include "media_data_source.h"
#include "cj_avplayer_utils.h"
#include "cj_common_ffi.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
class CJMediaDataSourceCallback : public IMediaDataSource, public NoCopyable {
public:
    explicit CJMediaDataSourceCallback(int64_t fileSize);
    virtual ~CJMediaDataSourceCallback();
    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1) override;
    int32_t GetSize(int64_t &size) override;
    int64_t GetCallbackId();
    void SetCallback(int64_t callbackId);
    void ClearCallbackReference();

    // This interface has been deprecated
    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    // This interface has been deprecated
    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;

private:
    int64_t size_ = -1;
    std::function<int32_t(const CArrUI8 mem, uint32_t length, int64_t pos)> cb_ = nullptr;
    int64_t callbackId_ = -1;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_DATA_SOURCE_CALLBACK_IMPL_H
