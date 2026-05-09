cmake_minimum_required(VERSION 3.14)

include(FetchContent)

FetchContent_Declare(
  base64
  GIT_REPOSITORY https://github.com/aklomp/base64
  GIT_TAG v0.5.0
)

FetchContent_MakeAvailable(base64)
