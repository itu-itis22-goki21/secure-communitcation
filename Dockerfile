FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY common.h common.cpp alice.cpp bob.cpp kdc.cpp ./

RUN g++ -std=c++17 -Wall -Wextra -pedantic kdc.cpp common.cpp -lssl -lcrypto -o kdc \
    && g++ -std=c++17 -Wall -Wextra -pedantic bob.cpp common.cpp -lssl -lcrypto -o bob \
    && g++ -std=c++17 -Wall -Wextra -pedantic alice.cpp common.cpp -lssl -lcrypto -o alice

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/kdc /app/bob /app/alice ./

CMD ["./alice"]
