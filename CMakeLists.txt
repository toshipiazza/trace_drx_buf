cmake_minimum_required (VERSION 3.0)
project (memtrace_simple)

add_library(memtrace_simple SHARED memtrace_simple.c utils.c)
add_library(instrace_simple SHARED instrace_simple.c utils.c)
add_library(bbtrace_simple SHARED  bbtrace_simple.cpp app.cpp utils.c)

find_package(DynamoRIO REQUIRED)

configure_DynamoRIO_client(memtrace_simple)
use_DynamoRIO_extension(memtrace_simple "drreg")
use_DynamoRIO_extension(memtrace_simple "drmgr")
use_DynamoRIO_extension(memtrace_simple "drutil")
use_DynamoRIO_extension(memtrace_simple "drx")

configure_DynamoRIO_client(instrace_simple)
use_DynamoRIO_extension(instrace_simple "drreg")
use_DynamoRIO_extension(instrace_simple "drmgr")
use_DynamoRIO_extension(instrace_simple "drutil")
use_DynamoRIO_extension(instrace_simple "drx")

configure_DynamoRIO_client(bbtrace_simple)
use_DynamoRIO_extension(bbtrace_simple "drreg")
use_DynamoRIO_extension(bbtrace_simple "drmgr")
use_DynamoRIO_extension(bbtrace_simple "drx")
use_DynamoRIO_extension(bbtrace_simple "droption")
