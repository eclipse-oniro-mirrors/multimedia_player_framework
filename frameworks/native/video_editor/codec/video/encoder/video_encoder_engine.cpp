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
#include "codec/video_encoder_engine.h"
#include "codec/video/encoder/video_encoder_engine_impl.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorEncode"};
}

static std::atomic<uint64_t> g_encoderId { 1 };
std::shared_ptr<IVideoEncoderEngine> IVideoEncoderEngine::Create(int fd,
    OH_AVFormat* videoFormat, std::weak_ptr<VideoEncodeCallback> cb)
{
    if (cb.expired()) {
        MEDIA_LOGE("create video encoder for video [%{public}d] failed, the parameter cb is nullptr.", fd);
        return nullptr;
    }

    if (videoFormat == nullptr) {
        MEDIA_LOGE("create video encoder for video [%{public}d] failed, the parameter videoFormat is nullptr.", fd);
        return nullptr;
    }

    auto engine = std::make_shared<VideoEncoderEngineImpl>(g_encoderId.fetch_add(1), fd, cb);
    auto error = engine->Init(videoFormat);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("init video encoder[id = %{public}" PRIu64 "] failed, error: %{public}d.", engine->GetId(), error);
        return nullptr;
    }
    return engine;
}

} // namespace Media
} // namespace OHOS
