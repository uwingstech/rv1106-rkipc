#!/bin/bash

PATH=${PWD}/arm-rockchip830-linux-uclibcgnueabihf/bin:$PATH

TOP=$(realpath "$(dirname "${BASH_SOURCE[0]}")")

alias push-rkipc='adb push ${TOP}/build/src/rv1106_ipc/rkipc /oem/usr/bin/rkipc'
alias stop-RkLunch='adb shell RkLunch-stop.sh'
alias stop-rkipc='adb shell killall -9 rkipc'
alias start-rkipc='adb shell rkipc -a /oem/usr/share/iqfiles &'
