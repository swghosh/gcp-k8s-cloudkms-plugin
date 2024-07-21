# Copyright 2019 Google, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# FROM golang:1.22 AS builder

# ENV GO111MODULE=on \
#   CGO_ENABLED=0 \
#   GOOS=linux \
#   GOARCH=amd64

# WORKDIR /src
# COPY . .

# RUN make build



# FROM registry.access.redhat.com/ubi9/ubi:latest

# COPY --from=builder /src/build/k8s-cloudkms-plugin /bin/k8s-cloudkms-plugin
# ENTRYPOINT ["/bin/k8s-cloudkms-plugin"]

FROM golang:1.22 AS builder
RUN go install -mod=readonly github.com/go-delve/delve/cmd/dlv@latest
WORKDIR /go/src/github.com/GoogleCloudPlatform/k8s-cloudkms-plugin
COPY . .
RUN go build -gcflags "all=-N -l" ./cmd/k8s-cloudkms-plugin/...

FROM registry.access.redhat.com/ubi9/ubi:latest
COPY --from=builder /go/bin/dlv /usr/bin/
COPY --from=builder /go/src/github.com/GoogleCloudPlatform/k8s-cloudkms-plugin/k8s-cloudkms-plugin /bin/
