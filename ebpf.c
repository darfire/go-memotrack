//go:build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef struct event_s {
  long addr;
  __u32 stack_id;
  __u64 tstamp;
  __u16 probe_id;
  __u64 pid_tgid;
} event_t;

#define STACK_SIZE 8

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096 * 32);
  __type(value, event_t);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, STACK_SIZE * sizeof(__u64));
  __uint(max_entries, 1024);
} stacks SEC(".maps");

int fill_event(struct pt_regs *ctx, long addr, event_t *event)
{
  long stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK);
  if (stack_id < 0) {
    return -1;
  }

  event->pid_tgid = bpf_get_current_pid_tgid();
  event->stack_id = stack_id;
  event->addr = addr;
  event->tstamp = bpf_ktime_get_ns();
  event->probe_id = bpf_get_attach_cookie(ctx);
  
  return 0;
}

SEC("uretprobe/malloc")
int uretprobe_malloc(struct pt_regs *ctx) {
  event_t *event;
  long ret = PT_REGS_RC(ctx);
  
  event = (event_t *) bpf_ringbuf_reserve(&events, sizeof(event_t), 0);
  
  if (!event) {
    return 0;
  }
  
  if (fill_event(ctx, ret, event) < 0) {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }
  
  bpf_ringbuf_submit(event, 0);
  
  return 0;
}

SEC("uprobe/free")
int uprobe_free(struct pt_regs *ctx) {
  event_t *event;
  long addr = PT_REGS_PARM1(ctx);
  
  event = (event_t *) bpf_ringbuf_reserve(&events, sizeof(event_t), 0);
  
  if (!event) {
    return 0;
  }
  
  if (fill_event(ctx, addr, event) < 0) {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }
  
  bpf_ringbuf_submit(event, 0);
  
  return 0;
}

SEC("uprobe/reference")
int uprobe_reference(struct pt_regs *ctx) {
  event_t *event;
  
  event = (event_t *) bpf_ringbuf_reserve(&events, sizeof(event_t), 0);
  
  if (!event) {
    return 0;
  }
  
  event->pid_tgid = bpf_get_current_pid_tgid();
  event->tstamp = bpf_ktime_get_ns();
  event->probe_id = bpf_get_attach_cookie(ctx);

  bpf_ringbuf_submit(event, 0);
  
  return 0;
}
  

char __license[] SEC("license") = "Dual MIT/GPL";