/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "media_parcel.h"
#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaParcel"};
}

namespace OHOS {
namespace Media {
static bool DoMarshalling(MessageParcel &parcel, const Format &format)
{
    auto dataMap = format.GetFormatMap();
    (void)parcel.WriteUint32(dataMap.size());
    for (auto it = dataMap.begin(); it != dataMap.end(); ++it) {
        (void)parcel.WriteString(it->first);
        (void)parcel.WriteUint32(it->second.type);

        switch (it->second.type) {
            case FORMAT_TYPE_INT32:
                (void)parcel.WriteInt32(it->second.val.int32Val);
                break;
            case FORMAT_TYPE_UINT32:
                (void)parcel.WriteUint32(it->second.val.uint32Val);
                break;
            case FORMAT_TYPE_INT64:
                (void)parcel.WriteInt64(it->second.val.int64Val);
                break;
            case FORMAT_TYPE_FLOAT:
                (void)parcel.WriteFloat(it->second.val.floatVal);
                break;
            case FORMAT_TYPE_DOUBLE:
                (void)parcel.WriteDouble(it->second.val.doubleVal);
                break;
            case FORMAT_TYPE_STRING:
                (void)parcel.WriteString(it->second.stringVal);
                break;
            case FORMAT_TYPE_ADDR:
                (void)parcel.WriteUInt8Vector(
                    std::vector<uint8_t>(it->second.addr, it->second.addr + it->second.size));
                break;
            default:
                MEDIA_LOGE("fail to Marshalling Key: %{public}s", it->first.c_str());
                return false;
        }
        MEDIA_LOGD("success to Marshalling Key: %{public}s", it->first.c_str());
    }
    return true;
}

bool MediaParcel::Marshalling(MessageParcel &parcel, const Format &format)
{
    auto res = DoMarshalling(parcel, format);
    auto vecMap = format.GetFormatVectorMap();
    if (!vecMap.empty()) {
        for (auto it = vecMap.begin(); it != vecMap.end(); ++it) {
            uint32_t vecSize = static_cast<uint32_t>(it->second.size());
            (void)parcel.WriteUint32(vecSize);
            if (vecSize == 0) {
                MEDIA_LOGW("Marshal FormatVectorMap, vector is empty!");
                (void)parcel.WriteUint32(0);
            } else {
                (void)parcel.WriteString(it->first);
            }

            for (uint32_t index = 0; index < vecSize; index++) {
                CHECK_AND_RETURN_RET(DoMarshalling(parcel, it->second[index]), false);
            }
        }
    } else {
        (void)parcel.WriteUint32(0); // vecSize is 0
    }
    return res;
}

static bool DoUnmarshalling(MessageParcel &parcel, Format &format)
{
    uint32_t size = parcel.ReadUint32();
    constexpr uint32_t MAX_PARCEL_SIZE = 256;
    CHECK_AND_RETURN_RET(size <= MAX_PARCEL_SIZE, false);
    for (uint32_t index = 0; index < size; index++) {
        std::string key = parcel.ReadString();
        uint32_t valType = parcel.ReadUint32();
        bool unMarshallRes = true;
        switch (valType) {
            case FORMAT_TYPE_INT32:
                (void)format.PutIntValue(key, parcel.ReadInt32());
                break;
            case FORMAT_TYPE_UINT32:
                (void)format.PutUintValue(key, parcel.ReadUint32());
                break;
            case FORMAT_TYPE_INT64:
                (void)format.PutLongValue(key, parcel.ReadInt64());
                break;
            case FORMAT_TYPE_FLOAT:
                (void)format.PutFloatValue(key, parcel.ReadFloat());
                break;
            case FORMAT_TYPE_DOUBLE:
                (void)format.PutDoubleValue(key, parcel.ReadDouble());
                break;
            case FORMAT_TYPE_STRING:
                (void)format.PutStringValue(key, parcel.ReadString());
                break;
            case FORMAT_TYPE_ADDR: {
                std::vector<uint8_t> vector;
                (void)parcel.ReadUInt8Vector(&vector);
                unMarshallRes = format.PutBuffer(key, vector.data(), vector.size());
                CHECK_AND_RETURN_RET_LOG(unMarshallRes, false, "Buffer unmarshalling failed");
                break;
            }
            default:
                MEDIA_LOGE("fail to Unmarshalling Key: %{public}s", key.c_str());
                return false;
        }
    }

    return true;
}

bool MediaParcel::Unmarshalling(MessageParcel &parcel, Format &format)
{
    auto res = DoUnmarshalling(parcel, format);
    uint32_t vecSize = parcel.ReadUint32();
    if (vecSize != 0) {
        constexpr uint32_t MAX_PARCEL_SIZE = 256;
        CHECK_AND_RETURN_RET(vecSize <= MAX_PARCEL_SIZE, false);
        std::string key = parcel.ReadString();
        std::vector<Format> vecFormat;
        for (uint32_t index = 0; index < vecSize; index++) {
            Format formatItem;
            if (!DoUnmarshalling(parcel, formatItem)) {
                return false;
            }
            vecFormat.emplace_back(formatItem);
        }
        (void)format.PutFormatVector(key, vecFormat);
    }

    return res;
}

bool MediaParcel::MetaMarshalling(MessageParcel &parcel, const Media::Format &format)
{
    Format *formatRef = const_cast<Format *>(&format);
    CHECK_AND_RETURN_RET_LOG(formatRef != nullptr, false, "formatRef is nullptr.");
    return formatRef->GetMeta()->ToParcel(parcel);
}

bool MediaParcel::MetaUnmarshalling(MessageParcel &parcel, Media::Format &format)
{
    auto meta = std::make_shared<Meta>();
    CHECK_AND_RETURN_RET_LOG(meta != nullptr, false, "create meta failed.");
    bool ret = meta->FromParcel(parcel) && format.SetMeta(std::move(meta));
    return ret;
}

} // namespace Media
} // namespace OHOS
