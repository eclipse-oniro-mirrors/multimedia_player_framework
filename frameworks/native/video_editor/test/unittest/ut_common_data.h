/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_VEF_UT_COMMON_DATA_H
#define OH_VEF_UT_COMMON_DATA_H

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "video_editor_impl.h"
#include "codec/video_decoder_engine.h"
#include "codec/video_encoder_engine.h"
#include <fcntl.h>
#include <iostream>

namespace OHOS {
namespace Media {

constexpr const char* WATER_MARK_DESC =
    "{\"imageEffect\":{\"filters\":[{\"name\":\"Brightness\",\"values\":"
    "{\"RESOURCE_DIRECTORY\":\"/sys_prod/resource/camera\"}}],\"name\":\"brandWaterMark\"}}";

constexpr const char* SURFACE_VERTEX_SHADER_CODE = R"(uniform mat4 uTexMatrix;
    attribute vec4 aPosition;
    attribute vec4 aTextureCoord;
    varying vec2 vTextureCoord;
    void main() {
        gl_Position = aPosition;
        vTextureCoord = (uTexMatrix * vec4(aTextureCoord.xy, 0.0, 1.0)).xy;
    }
    )";

constexpr const char* SURFACE_ROTATE_FRAGMENT_SHADER_CODE = R"(
    precision mediump float;
    varying vec2 vTextureCoord;
    uniform sampler2D sTexture;
    void main() {
        gl_FragColor = texture2D(sTexture, vTextureCoord);
    }
    )";

class CompositionCallbackTesterImpl : public CompositionCallback {
public:
    CompositionCallbackTesterImpl() = default;
    virtual ~CompositionCallbackTesterImpl() = default;
    void onResult(VEFResult result, VEFError errorCode) override
    {
        result_ = result;
    }
    void onProgress(uint32_t progress) override
    {
        progress_ = progress;
    }
private:
    VEFResult result_ = VEFResult::UNKNOWN;
    uint32_t progress_ = 0;
};

class VideoDecodeCallbackTester : public VideoDecodeCallback {
public:
    VideoDecodeCallbackTester() = default;
    virtual ~VideoDecodeCallbackTester() = default;
    void OnDecodeFrame(uint64_t pts) override
    {
        pts_ = pts;
    };
    void OnDecodeResult(CodecResult result) override
    {
        result_ = result;
    };

    uint64_t pts_ { 0 };
    CodecResult result_ { CodecResult::FAILED };
};

class VideoEncodeCallbackTester : public VideoEncodeCallback {
public:
    VideoEncodeCallbackTester() = default;
    virtual ~VideoEncodeCallbackTester() = default;
    void OnEncodeFrame(uint64_t pts) override
    {
        pts_ = pts;
    };
    void OnEncodeResult(CodecResult result) override
    {
        result_ = result;
    };

    uint64_t pts_ { 0 };
    CodecResult result_ { CodecResult::FAILED };
};

class VideoResource {
public:
    virtual ~VideoResource() {};
    static VideoResource& instance()
    {
        static VideoResource instance;
        return instance;
    }

    int32_t getFileResource(std::string& fileName)
    {
        const std::string videoFilePath = "/data/test/" + fileName;
        int32_t srcFd = open(videoFilePath.c_str(), O_RDWR);
        if (srcFd <= 0) {
            std::cout << "Open file failed" << std::endl;
            return -1;
        }
        return srcFd;
    }

    VideoEncodeParam getEncodeParam(int32_t& srcFd, std::shared_ptr<IVideoDecoderEngine> decoderEngine)
    {
        VideoEncodeParam enCodeParam;
        if (decoderEngine == nullptr) {
            std::cout << "decoderEngine is nullptr, get enCodeParam failed" << std::endl;
            return enCodeParam;
        }
        enCodeParam.videoTrunkFormat = decoderEngine->GetVideoFormat();
        enCodeParam.audioTrunkFormat = decoderEngine->GetAudioFormat();
        enCodeParam.muxerParam.targetFileFd = srcFd;
        enCodeParam.muxerParam.avOutputFormat = AV_OUTPUT_FORMAT_MPEG_4;
        enCodeParam.muxerParam.rotation = decoderEngine->GetRotation();
        return enCodeParam;
    }

private:
    VideoResource() {};
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_UT_COMMON_DATA_H