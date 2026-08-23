#pragma once

// The Windows SDK needs WinSock2 declarations before its extension headers.
// clang-format off
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <MSWSock.h>
#include "windns_compat.h"
// clang-format on
