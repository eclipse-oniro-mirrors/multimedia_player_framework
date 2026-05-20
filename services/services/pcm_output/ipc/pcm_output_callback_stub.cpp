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

#include "pcm_output_callback_stub.h"
#include "media_errors.h"
#include "media_log.h"
#include "native_avbuffer.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PCMOutputCallbackStub"};
}

namespace OHOS {
namespace Media {
PCMOutputCallbackStub::PCMOutputCallbackStub()
{
    MEDIA_LOGD("PCMOutputCallbackStub ctor called");
}

int32_t PCMOutputCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    CHECK_AND_RETURN_RET_LOG(data.ReadInterfaceToken() == PCMOutputCallbackStub::GetDescriptor(), ERR_INVALID_OPERATION,
        "Invalid descriptor");

    switch (code) {
        case IStandardPCMOutputCallback::ON_PCM_OUTPUT: {
            std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
            CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MSERR_NO_MEMORY, "Failed to create AVBuffer");

            bool ret = buffer->ReadFromMessageParcel(data);
            CHECK_AND_RETURN_RET(ret, MSERR_INVALID_VAL);

            OnPCMOutput(buffer);
            return ERR_OK;
        }
        case IStandardPCMOutputCallback::ON_PCM_PROCESSOR: {
            std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer();
            CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MSERR_NO_MEMORY, "Failed to create AVBuffer");

            bool ret = buffer->ReadFromMessageParcel(data);
            CHECK_AND_RETURN_RET(ret, ERR_INVALID_OPERATION);

            OnPCMProcessor(buffer);

            buffer->WriteToMessageParcel(reply);
            return ERR_OK;
        }
        default: {
            MEDIA_LOGE("Unknown request code: %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

void PCMOutputCallbackStub::OnPCMOutput(const std::shared_ptr<AVBuffer> &buffer)
{
    MEDIA_LOGD("PCMOutputCallbackStub::OnPCMOutput");
    std::shared_ptr<PlayerCallback> callback;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        callback = pcmCallback_;
    }
    CHECK_AND_RETURN(callback != nullptr);
    callback->OnPCMOutput(buffer);
}

void PCMOutputCallbackStub::OnPCMProcessor(const std::shared_ptr<AVBuffer> &buffer)
{
    MEDIA_LOGD("PCMOutputCallbackStub::OnPCMProcessor");
    std::shared_ptr<PlayerCallback> callback;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        callback = pcmCallback_;
    }
    CHECK_AND_RETURN(callback != nullptr);
    callback->OnPCMProcessor(buffer);
}

void PCMOutputCallbackStub::SetPCMCallback(const std::shared_ptr<PlayerCallback> &callback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    MEDIA_LOGD("PCMOutputCallbackStub::SetPCMCallback");
    pcmCallback_ = callback;
}
} // namespace Media
} // namespace OHOS
