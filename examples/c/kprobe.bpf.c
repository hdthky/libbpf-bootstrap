// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

typedef struct string_t {
	u8 s[128];
} string_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, s32);
	__type(value, string_t);
} hm SEC(".maps");

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;
	char filename[128];
	filename[0] = '@';

	pid = bpf_get_current_pid_tgid() >> 32;
	char * np;
	bpf_probe_read(&np, sizeof(np), &name->name);
	s32 idx = 0;
	string_t *s = bpf_map_lookup_elem(&hm, &idx);
	if (s != NULL) {
		bpf_probe_read_str(s, 128, np+1);
	}
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{

	return 0;
}
