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
#ifndef HELPER_DATA_SOURCE_CALLBACK_TAIHE_H
#define HELPER_DATA_SOURCE_CALLBACK_TAIHE_H

#include <mutex>
#include "media_ani_common.h"
#include "media_data_source.h"
#include "nocopyable.h"
#include "event_handler.h"

namespace OHOS {
namespace Media {
using DataSrcCallback = taihe::callback<int32_t(taihe::array_view<uint8_t>, int64_t, taihe::optional_view<int64_t>)>;

struct HelperDataSourceTHCallback {
    HelperDataSourceTHCallback(const std::string &callbackName, const std::shared_ptr<AVSharedMemory> &mem,
        uint32_t length, int64_t pos)
        :callbackName_(callbackName), memory_(mem), length_(length), pos_(pos) {
    }
    ~HelperDataSourceTHCallback();
    void WaitResult();
    std::weak_ptr<ANI::Media::AutoRef> callback_;
    std::string callbackName_;
    std::shared_ptr<AVSharedMemory> memory_;
    uint32_t length_;
    int64_t pos_;
    int32_t readSize_ = 0;
    std::mutex mutexCond_;
    std::condition_variable cond_;
    bool setResult_ = false;
    bool isExit_ = false;
};

struct HelperDataSourceTHCallbackWraper {
    std::weak_ptr<HelperDataSourceTHCallback> cb_;
};

class HelperDataSourceCallback : public IMediaDataSource, public OHOS::NoCopyable {
public:
    HelperDataSourceCallback(ani_env *env, int64_t fileSize);
    virtual ~HelperDataSourceCallback();
    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1) override;
    int32_t GetSize(int64_t &size) override;
    void SaveCallbackReference(const std::string &name, std::shared_ptr<ANI::Media::AutoRef> ref);
    int32_t GetCallback(const std::string &name, std::shared_ptr<uintptr_t> &callback);
    void ClearCallbackReference();

    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
private:
    void UvWork(HelperDataSourceTHCallbackWraper *cbWrap,
        std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler);
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<ANI::Media::AutoRef>> refMap_;
    int64_t size_ = -1;
    std::shared_ptr<HelperDataSourceTHCallback> cb_ = nullptr;
};
} // namespace Media
} // namespace OHOS
#endif // HELPER_DATA_SOURCE_CALLBACK_H
