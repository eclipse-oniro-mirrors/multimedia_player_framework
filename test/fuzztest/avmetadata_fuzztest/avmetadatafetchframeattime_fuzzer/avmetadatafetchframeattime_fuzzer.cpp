/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "avmetadatafetchframeattime_fuzzer.h"
#include <iostream>
#include "aw_common.h"
#include "string_ex.h"
#include "media_errors.h"
#include "directory_ex.h"
#include "window_option.h"
#include "image_type.h"


using namespace std;
using namespace OHOS;
using namespace Media;
using namespace PlayerTestParam;

namespace OHOS {
namespace Media {
AVMetadataFetchFrameAtTimeFuzzer::AVMetadataFetchFrameAtTimeFuzzer()
{
}

AVMetadataFetchFrameAtTimeFuzzer::~AVMetadataFetchFrameAtTimeFuzzer()
{
}

bool AVMetadataFetchFrameAtTimeFuzzer::FuzzAVMetadataFetchFrameAtTime(uint8_t *data, size_t size)
{
    constexpr int32_t AV_METADATA_QUERY_OPTION_LIST = 4;
    constexpr int32_t AV_COLOR_FORMAT_LIST = 11;
    constexpr int32_t DATA_INDEX = 0;
    constexpr int32_t DATA_INDEX_OFFSET = 4;

    std::shared_ptr<AVMetadataHelper> avmetadata = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avmetadata == nullptr) {
        return false;
    }

    const string path = "/data/test/media/H264_AAC.mp4";
    if (MetaDataSetSource(path, avmetadata) != 0) {
        avmetadata->Release();
        return false;
    }

    int32_t avMetadataQueryOption[AV_METADATA_QUERY_OPTION_LIST] {
        AV_META_QUERY_NEXT_SYNC,
        AV_META_QUERY_PREVIOUS_SYNC,
        AV_META_QUERY_CLOSEST_SYNC,
        AV_META_QUERY_CLOSEST
    };

    int32_t reproducibleRandom = abs((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3]));
    int32_t option = avMetadataQueryOption[reproducibleRandom % AV_METADATA_QUERY_OPTION_LIST];
    PixelFormat colorFormats[AV_COLOR_FORMAT_LIST] {
        PixelFormat::UNKNOWN,
        PixelFormat::ARGB_8888,
        PixelFormat::RGB_565,
        PixelFormat::RGBA_8888,
        PixelFormat::BGRA_8888,
        PixelFormat::RGB_888,
        PixelFormat::ALPHA_8,
        PixelFormat::RGBA_F16,
        PixelFormat::NV21,
        PixelFormat::NV12,
        PixelFormat::CMYK
    };
    PixelFormat colorFormat = colorFormats[data[DATA_INDEX] % AV_COLOR_FORMAT_LIST];

    struct PixelMapParams pixelMapParams = {*reinterpret_cast<int32_t *>(data),
                                            *reinterpret_cast<int32_t *>(data + DATA_INDEX_OFFSET), colorFormat};
    
    std::shared_ptr<PixelMap> retFetchFrameAtTime =
        avmetadata->FetchFrameAtTime(*reinterpret_cast<int64_t *>(data), option, pixelMapParams);

    if (retFetchFrameAtTime != 0) {
        avmetadata->Release();
        return true;
    }
    avmetadata->Release();
    return true;
}
}

bool FuzzTestAVMetadataFetchFrameAtTime(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < sizeof(int64_t)) {
        return 0;
    }
    AVMetadataFetchFrameAtTimeFuzzer metadata;
    return metadata.FuzzAVMetadataFetchFrameAtTime(data, size);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzTestAVMetadataFetchFrameAtTime(data, size);
    return 0;
}
