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

#include "render_general_program.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}
RenderGeneralProgram::RenderGeneralProgram(RenderContext* context, const std::string& vss, const std::string& fss)
    : RenderProgram(context), vss_(vss), fss_(fss)
{
    SetTag("RenderGeneralProgram");
}

bool RenderGeneralProgram::Init()
{
    MEDIA_LOGD("RenderGeneralProgram Init begin");
    std::lock_guard<ffrt::mutex> lk(m_renderLock);
    if (IsReady()) {
        return true;
    }
    program_ = GLUtils::CreateProgram(vss_, fss_);
    SetReady(program_ > 0);
    MEDIA_LOGD("RenderGeneralProgram Init end");
    return program_ > 0;
}

bool RenderGeneralProgram::Release()
{
    MEDIA_LOGD("RenderGeneralProgram Release begin");
    if (!IsReady()) {
        return false;
    }
    glDeleteProgram(program_);
    GLUtils::CheckError(__FILE__, __LINE__);
    program_ = 0;
    SetReady(false);
    MEDIA_LOGD("RenderGeneralProgram Release end");
    return true;
}
}
}