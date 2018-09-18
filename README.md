# ebpf_dropper

`ebpf_dropper` is a small eBPF program intended to be attached to `tc` and provides tools to drop TCP segments
based on TCP flags or payload. `ebpf_dropper` does not depend on any external library (e.g. bcc) 
except the libraries provides by the Linux kernel itself.

## example
`An example is provided with `ebpf_dropper` itself. The two user-defined functions are modified in order to drop
packets having the `PSH` flag set and containing `DROPME` at the end of the TCP payload. It can for example be used
to generate tail-losses.
