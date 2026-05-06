/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "pcm_output_callback_proxy.h"
#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PCMOutputCallbackProxy"};
}

namespace OHOS {
namespace Media {
PCMOutputCallbackProxy::PCMOutputCallbackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IStandardPCMOutputCallback>(impl)
{
    MEDIA_LOGD("PCMOutputCallbackProxy ctor called");
}

void PCMOutputCallbackProxy::OnPCMOutput(const std::shared_ptr<AVBuffer> &buffer)
{
    CHECK_AND_RETURN_LOG(buffer != nullptr, "buffer is nullptr");

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    bool token = data.WriteInterfaceToken(PCMOutputCallbackProxy::GetDescriptor());
    CHECK_AND_RETURN_LOG(token, "Failed to write descriptor!");

    // Write AVBuffer using WriteToMessageParcel
    bool ret = buffer->WriteToMessageParcel(data);
    CHECK_AND_RETURN_LOG(ret, "Failed to write buffer to parcel!");

    int32_t error = Remote()->SendRequest(IStandardPCMOutputCallback::ON_PCM_OUTPUT, data, reply, option);
    CHECK_AND_RETURN_LOG(error == ERR_OK, "OnPCMOutput failed, error: %{public}d", error);
}
} // namespace Media
} // namespace OHOS
