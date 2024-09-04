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
#include "composite_engine/composite_engine.h"
#include "composite_engine/impl/video_composite_engine.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoComposite"};
}

static std::atomic_uint64_t g_compositeEngineId{ 1 };
std::shared_ptr<ICompositeEngine> ICompositeEngine::CreateCompositeEngine(const std::shared_ptr<IDataCenter>& dc)
{
    if (dc == nullptr) {
        MEDIA_LOGE("create video composite engine failed, dataCenter is nullptr.");
        return nullptr;
    }
    auto engine = std::make_shared<VideoCompositeEngine>(g_compositeEngineId.fetch_add(1));
    auto err = engine ->Init(dc);
    if (err != VEFError::ERR_OK) {
        MEDIA_LOGE("init composite engine[id = %{public}" PRIu64 "] failed, err: %{public}d.", engine->GetId(), err);
        return nullptr;
    }
    return engine;
}

} // namespace Media
} // namespace OHOS
