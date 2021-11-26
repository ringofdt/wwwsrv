#!/usr/bin/env bash
GIT_COMMIT=$(git rev-parse --short HEAD)

CMDNAME=wwwsrv
APP=$CMDNAME.app
TARGET=$CMDNAME-$GIT_COMMIT-linux-amd64

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
SRC=$WORKDIR/cmd/$CMDNAME

case $1 in
run)
    cd $SRC && go run . $@
    ;;
build)
    DEST=$WORKDIR/dist/$CMDNAME
    BIN=bin
    DESTBIN=$DEST/$BIN
    mkdir -p $DESTBIN
    OUTPUT=$DESTBIN/$TARGET
    SOURCE=$SRC/*.go

    rm $DESTBIN/*-linux-amd64 && echo "cleaning $DESTBIN/*-linux-amd64"
    echo "building: $DESTBIN/$TARGET"
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags "-X main.GitCommit=$GIT_COMMIT" -o $OUTPUT $SOURCE &&
        cd $DEST && ln -svf $BIN/$TARGET $APP && cd -

    ;;
*)
    echo "usage: xyz {run|build}"
    ;;
esac
exit 0
