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
#include "utils.h"

/* Each ins_ref_t describes an executed instruction. */
typedef struct _ins_ref_t {
    app_pc pc;
    int opcode;
} ins_ref_t;

/* Max number of ins_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_INS_REFS 8192
/* The maximum size of buffer for holding ins_refs. */
#define MEM_BUF_SIZE (sizeof(ins_ref_t) * MAX_NUM_INS_REFS)

/* thread private log file and counter */
typedef struct {
    file_t     log;
    FILE      *logf;
} per_thread_t;

static drx_buf_t *trace_buffer;
static int      tls_idx;

static client_id_t client_id;

static void
instrace(void *drcontext, void *buf_base, size_t size)
{
    per_thread_t *data;
    ins_ref_t *ins_ref, *buf_ptr;

    data    = drmgr_get_tls_field(drcontext, tls_idx);
    buf_ptr = (ins_ref_t *)((byte *)buf_base + size);
    /* Example of dumped file content:
     *   0x7f59c2d002d3: call
     *   0x7ffeacab0ec8: mov
     */
    /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
     * for repeated printing that dominates performance, as the printing does here.
     */
    for (ins_ref = (ins_ref_t *)buf_base; ins_ref < buf_ptr; ins_ref++) {
        /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
        fprintf(data->logf, PIFX",%s\n", (ptr_uint_t)ins_ref->pc,
                decode_opcode_name(ins_ref->opcode));
    }
}

static void
insert_save_opcode(void *drcontext, instrlist_t *ilist, instr_t *where,
                   reg_id_t base, reg_id_t scratch, int opcode)
{
    drx_buf_insert_buf_store(drcontext, trace_buffer, ilist, where, base, scratch,
                             OPND_CREATE_INT16(opcode), OPSZ_2,
                             offsetof(ins_ref_t, opcode));
}

static void
insert_save_pc(void *drcontext, instrlist_t *ilist, instr_t *where,
               reg_id_t base, reg_id_t scratch, app_pc pc)
{
    drx_buf_insert_buf_store(drcontext, trace_buffer, ilist, where, base, scratch,
                             OPND_CREATE_INTPTR(pc), OPSZ_PTR,
                             offsetof(ins_ref_t, pc));
}

/* insert inline code to add an instruction entry into the buffer */
static void
instrument_instr(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
        DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
        DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }

    drx_buf_insert_load_buf_ptr(drcontext, trace_buffer, ilist, where, reg_ptr);
    insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp,
                   instr_get_app_pc(where));
    insert_save_opcode(drcontext, ilist, where, reg_ptr, reg_tmp,
                       instr_get_opcode(where));
    drx_buf_insert_update_buf_ptr(drcontext, trace_buffer, ilist, where, reg_ptr,
                                  DR_REG_NULL, sizeof(ins_ref_t));

    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

/* For each app instr, we insert inline code to fill the buffer. */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb,
                      instr_t *instr, bool for_trace,
                      bool translating, void *user_data)
{
    /* we don't want to auto-predicate any instrumentation */
    drmgr_disable_auto_predication(drcontext, bb);

    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    /* insert code to add an entry to the buffer */
    instrument_instr(drcontext, bb, instr);

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    data->log = log_file_open(client_id, drcontext, NULL /* using client lib path */,
                              "instrace",
#ifndef WINDOWS
                              DR_FILE_CLOSE_ON_FORK |
#endif
                              DR_FILE_ALLOW_LARGE);
    data->logf = log_stream_from_file(data->log);
    fprintf(data->logf, "Format: <instr address>,<opcode>\n");
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
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
    dr_set_client_name("DynamoRIO Sample Client 'instrace'",
                       "http://dynamorio.org/issues");
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

    trace_buffer = drx_buf_create_trace_buffer(MEM_BUF_SIZE, instrace);
    DR_ASSERT(trace_buffer != NULL);

    /* make it easy to tell, by looking at log file, which client executed */
    dr_log(NULL, LOG_ALL, 1, "Client 'instrace' initializing\n");
}
