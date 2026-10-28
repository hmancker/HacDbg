cmake_minimum_required(VERSION 3.24)

project(HacDbgQt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

set(HACDBG_QT_SOURCES
    src/main.cpp
    src/CoreSession.cpp
    src/CoreSession.h
    src/CommandView.cpp
    src/CommandView.h
    src/DisassemblyView.cpp
    src/DisassemblyView.h
    src/RegisterView.cpp
    src/RegisterView.h
    src/HexDumpView.cpp
    src/HexDumpView.h
    src/StackView.cpp
    src/StackView.h
    src/CpuView.cpp
    src/CpuView.h
    src/BreakpointView.cpp
    src/BreakpointView.h
    src/MonitorView.cpp
    src/MonitorView.h
    src/SymbolView.cpp
    src/SymbolView.h
    src/ProcessThreadView.cpp
    src/ProcessThreadView.h
    src/TraceWindow.cpp
    src/TraceWindow.h
    src/MainWindow.cpp
    src/MainWindow.h
    src/Format.h
    app.manifest)

qt_add_executable(HacDbgQt WIN32 ${HACDBG_QT_SOURCES})

target_include_directories(HacDbgQt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../usermode/api"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../gui/HacDbgTrace/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../shared")

target_compile_definitions(HacDbgQt PRIVATE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE)

if(MSVC)
    target_compile_options(HacDbgQt PRIVATE
        /W4
        /WX
        /utf-8
        /permissive-
        /Zc:__cplusplus
        /external:W0
        /external:anglebrackets)
endif()

target_link_libraries(HacDbgQt PRIVATE Qt6::Widgets advapi32)

if(MSVC)
    target_link_options(HacDbgQt PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
endif()

set_target_properties(HacDbgQt PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../build/x64")

if(WIN32)
    get_target_property(HACDBG_QMAKE Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(HACDBG_QT_BIN "${HACDBG_QMAKE}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${HACDBG_QT_BIN}" REQUIRED)
    add_custom_command(TARGET HacDbgQt POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}" --no-translations --no-system-dxc-compiler "$<TARGET_FILE:HacDbgQt>"
        COMMENT "Deploying Qt runtime"
        VERBATIM)
endif()
