/* ******************************************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 Massachusetts Institute of Technology  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <stdio.h>
#include <stddef.h> /* for offsetof */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drx.h"
#include "droption.h"

#include "utils.h"
#include "app.h"

#define MAX_NUM_MEM_REFS 4096
#define MEM_BUF_SIZE (sizeof(app_pc) * MAX_NUM_MEM_REFS)

static drx_buf_t *trace_buffer;
static int tls_idx;

/* thread private log file and counter */
typedef struct {
    file_t     log;
    FILE      *logf;
} per_thread_t;

static client_id_t client_id;

static void
bbtrace(void *drcontext, void *buf_base, size_t size)
{
    per_thread_t *data;
    app_pc *bb;
    app_pc *bb_top = (app_pc *)((char *)buf_base + size);

    data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
     * for repeated printing that dominates performance, as the printing does here.
     */
    for (bb = (app_pc *)buf_base; bb < bb_top; bb++)
        fprintf(data->logf, "%p\n", *bb);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
                      instr_t *instr, bool for_trace,
                      bool translating, void *user_data)
{
    reg_id_t reg_ptr, reg_tmp;
    app_pc pc;

    if (for_trace) {
        dr_printf("WARNING: please specify -disable_traces or resulting "
                  "trace may seem innacurate\n");
    }

    if (!drmgr_is_first_instr(drcontext, instr))
        return DR_EMIT_DEFAULT;
    if (app_should_ignore_tag(tag))
        return DR_EMIT_DEFAULT;

    drmgr_disable_auto_predication(drcontext, bb);

    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_ptr) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, instr, NULL, &reg_tmp) != DRREG_SUCCESS) {
        DR_ASSERT(false);
        return DR_EMIT_DEFAULT;
    }

    pc = dr_fragment_app_pc(tag);
    drx_buf_insert_load_buf_ptr(drcontext, trace_buffer, bb, instr, reg_ptr);
    /* write the app_pc to the buffer */
    drx_buf_insert_buf_store(drcontext, trace_buffer, bb, instr, reg_ptr, reg_tmp,
                             OPND_CREATE_INTPTR(pc), OPSZ_PTR, 0);
    drx_buf_insert_update_buf_ptr(drcontext, trace_buffer, bb, instr, reg_ptr,
                                  DR_REG_NULL, sizeof(app_pc));

    if (drreg_unreserve_register(drcontext, bb, instr, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, instr, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    data->log = log_file_open(client_id, drcontext, NULL /* using client lib path */,
                              "bbtrace",
#ifndef WINDOWS
                              DR_FILE_CLOSE_ON_FORK |
#endif
                              DR_FILE_ALLOW_LARGE);
    data->logf = log_stream_from_file(data->log);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    log_stream_close(data->logf); /* closes fd too */
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
event_exit(void)
{
    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);

    drmgr_exit();

    drx_buf_free(trace_buffer);
    drx_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    drreg_options_t ops = {sizeof(ops), 3, false};
    droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL);

    app_init();
    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drx_init())
        DR_ASSERT(false);

    /* register events */
    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/,
                                                 event_app_instruction,
                                                 NULL))
        DR_ASSERT(false);

    client_id = id;

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);

    trace_buffer = drx_buf_create_trace_buffer(MEM_BUF_SIZE, bbtrace);
    DR_ASSERT(trace_buffer != NULL);

    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, LOG_ALL, 1, "Client 'bbtrace' initializing\n");
}
