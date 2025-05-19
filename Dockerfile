#################################################################
# Step 1: Build the companion app                               #
#################################################################
FROM gradle:8.5-jdk17 AS companion-builder
WORKDIR /usr/src/app

# Install Android SDK
RUN apt-get update && apt-get install -y wget unzip

RUN mkdir -p /sdk && \
  cd /sdk && \
  wget https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip -O cmdline-tools.zip && \
  unzip cmdline-tools.zip -d cmdline-tools-temp && \
  rm cmdline-tools.zip && \
  mkdir -p /sdk/cmdline-tools/latest && \
  mv cmdline-tools-temp/cmdline-tools/* /sdk/cmdline-tools/latest/ && \
  rm -rf cmdline-tools-temp

ENV ANDROID_SDK_ROOT=/sdk
ENV ANDROID_HOME=/sdk
ENV PATH="$PATH:/sdk/cmdline-tools/latest/bin:/sdk/platform-tools"

RUN yes | sdkmanager --licenses
RUN sdkmanager \
    "platform-tools" \
    "platforms;android-35" \
    "build-tools;35.0.0"

# Copy package.json for the version
COPY package.json /usr/src/app/package.json
COPY companion /usr/src/app/companion
RUN cd ./companion && ./gradlew assembleRelease

#################################################################
# Step 2: Build everything using the `npm build` command        #
#################################################################
FROM node:20.17.0-bullseye-slim AS main-builder
WORKDIR /usr/src/app
COPY . .
RUN npm install --ignore-scripts && \
  npx fetch-scrcpy-server 3.1 && \
  npm run scrcpy && \ 
  npm run build:setup && \ 
  npm run build:client && \ 
  npm run build:server && \ 
  npm run copy-files
RUN mkdir dist/resources && cp resources/scrcpy-server.jar dist/resources/scrcpy-server.jar
COPY --from=companion-builder /usr/src/app/companion/droidground-companion.dex dist/resources/droidground-companion.dex

#################################################################
# Step 3: Pack everything together                              #
#################################################################
FROM node:20.17.0-bullseye-slim
WORKDIR /usr/src/app
ENV NODE_ENV=production
COPY --from=main-builder /usr/src/app/dist .
COPY run.sh ./
COPY package*.json ./

RUN apt-get update && \
  apt-get install -y \
    python3 \
    python3-pip \
    build-essential \
    curl \
    git \
    unzip \
    libglib2.0-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and install platform-tools (ADB)
RUN curl -o platform-tools.zip https://dl.google.com/android/repository/platform-tools-latest-linux.zip \
 && unzip platform-tools.zip \
 && rm platform-tools.zip \
 && mv platform-tools /opt/platform-tools \
 && ln -s /opt/platform-tools/adb /usr/local/bin/adb

RUN pip3 install frida-tools
RUN npm ci --only=production --ignore-scripts
# If I don't do this the binding is missing
RUN npm i frida
RUN chmod +x run.sh

ENTRYPOINT ["./run.sh"]