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

#include "surface_texture.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}
const int WAIT_TIMEOUT_MS = 10;

void SurfaceTexture::OnFrameAvailable(void* context)
{
    if (context == nullptr) {
        MEDIA_LOGE("OnFrameAvailable failed, context is nullptr.");
        return;
    }
    auto surfaceTexture = static_cast<SurfaceTexture*>(context);
    std::unique_lock lk(surfaceTexture->frameLock_);
    surfaceTexture->frameNum_++;
    surfaceTexture->frameCv_.notify_all();
}

void SurfaceTexture::AwaitNativeImage()
{
    std::unique_lock lk(frameLock_);
    if (frameNum_ > 0) {
        frameNum_--;
        return;
    }
    frameCv_.wait_for(lk, std::chrono::milliseconds(WAIT_TIMEOUT_MS), [this]() { return frameNum_ > 0; });
    if (frameNum_ == 0) {
        MEDIA_LOGW("[Render] Wait for frame available timeout, update directly");
        return;
    }
    frameNum_--;
}
}
}