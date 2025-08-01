

set(CMAKE_C_COMPILER    arm-rockchip830-linux-uclibcgnueabihf-gcc CACHE INTERNAL "C compiler")
set(CMAKE_CXX_COMPILER  arm-rockchip830-linux-uclibcgnueabihf-g++ CACHE INTERNAL "C++ compiler")
set(CMAKE_ASM_COMPILER  arm-rockchip830-linux-uclibcgnueabihf-gcc CACHE INTERNAL "ASM compiler")
set(CMAKE_LINKER        arm-rockchip830-linux-uclibcgnueabihf-ld CACHE INTERNAL "Linker")
set(CMAKE_AR            arm-rockchip830-linux-uclibcgnueabihf-ar CACHE INTERNAL "Archiver")
set(CMAKE_NM            arm-rockchip830-linux-uclibcgnueabihf-nm CACHE INTERNAL "Name lister")
set(CMAKE_OBJCOPY       arm-rockchip830-linux-uclibcgnueabihf-objcopy CACHE INTERNAL "Object copy")
set(CMAKE_OBJDUMP       arm-rockchip830-linux-uclibcgnueabihf-objdump CACHE INTERNAL "Object dump")
set(CMAKE_STRIP         arm-rockchip830-linux-uclibcgnueabihf-strip CACHE INTERNAL "Strip")

# System name
set(CMAKE_SYSTEM_NAME Linux)

# Cross compilation root paths
set(TOOLCHAIN_SYSROOT ${PROJECT_SOURCE_DIR}/arm-rockchip830-linux-uclibcgnueabihf/bin/../arm-rockchip830-linux-uclibcgnueabihf/sysroot CACHE INTERNAL "Toolchain sysroot" )
