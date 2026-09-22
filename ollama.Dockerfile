FROM scratch AS model

ADD --checksum=sha256:60e05f2100071479f596b964f89f510f057ce397ea22f2833a0cfe029bfc2463 \
    https://registry.ollama.ai/v2/library/qwen2.5-coder/blobs/sha256:60e05f2100071479f596b964f89f510f057ce397ea22f2833a0cfe029bfc2463 \
    /models/blobs/sha256-60e05f2100071479f596b964f89f510f057ce397ea22f2833a0cfe029bfc2463
ADD --checksum=sha256:66b9ea09bd5b7099cbb4fc820f31b575c0366fa439b08245566692c6784e281e \
    https://registry.ollama.ai/v2/library/qwen2.5-coder/blobs/sha256:66b9ea09bd5b7099cbb4fc820f31b575c0366fa439b08245566692c6784e281e \
    /models/blobs/sha256-66b9ea09bd5b7099cbb4fc820f31b575c0366fa439b08245566692c6784e281e
ADD --checksum=sha256:1e65450c30670713aa47fe23e8b9662bdf4065e81cc8e3cbfaa98924fcc0d320 \
    https://registry.ollama.ai/v2/library/qwen2.5-coder/blobs/sha256:1e65450c30670713aa47fe23e8b9662bdf4065e81cc8e3cbfaa98924fcc0d320 \
    /models/blobs/sha256-1e65450c30670713aa47fe23e8b9662bdf4065e81cc8e3cbfaa98924fcc0d320
ADD --checksum=sha256:832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e \
    https://registry.ollama.ai/v2/library/qwen2.5-coder/blobs/sha256:832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e \
    /models/blobs/sha256-832dd9e00a68dd83b3c3fb9f5588dad7dcf337a0db50f7d9483f310cd292e92e
ADD --checksum=sha256:d9bb33f2786931fea42f50936a2424818aa2f14500638af2f01861eb2c8fb446 \
    https://registry.ollama.ai/v2/library/qwen2.5-coder/blobs/sha256:d9bb33f2786931fea42f50936a2424818aa2f14500638af2f01861eb2c8fb446 \
    /models/blobs/sha256-d9bb33f2786931fea42f50936a2424818aa2f14500638af2f01861eb2c8fb446
COPY qwen2.5-coder-7b.json /models/manifests/registry.ollama.ai/library/qwen2.5-coder/7b

FROM ollama/ollama:latest@sha256:5a5d014aa774f78ebe1340c0d4afc2e35afc12a2c3b34c84e71f78ea20af4ba3
COPY --from=model /models/ /root/.ollama/models/
