// XDP minimo de prueba.
// Solo cuenta paquetes que entran por la interfaz a la que se atacha.
// Sirve para validar el toolchain BCC + kernel + driver antes de meter
// la logica de filtrado y de NAT.

BPF_HASH(packet_count, u32, u64);

int xdp_counter(struct xdp_md *ctx) {
    u32 key = 0;
    u64 zero = 0;
    u64 *count = packet_count.lookup_or_try_init(&key, &zero);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;
}
