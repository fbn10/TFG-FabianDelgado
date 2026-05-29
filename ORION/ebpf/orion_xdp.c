// Programa XDP de ORION.
//
// Funcionalidades, en este orden por paquete entrante:
//   1) Filtrado por reglas (IP, puerto, protocolo, rate-limit pps/bps).
//   2) NAT 1-a-1 stateless (cliente <-> internet).
//
// El filtrado se evalua antes del NAT: si una regla dropea, ahorramos
// el trabajo de reescribir cabeceras y checksums.
//
// (BCC inyecta XDP_PASS, struct xdp_md, etc., no hace falta linux/bpf.h)

#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>


// Filtrado
// Maximo de reglas que el programa evalua por paquete.
// 16 es un buen compromiso: el verifier desenrolla bien el bucle y la
// complejidad total del programa eBPF se mantiene baja. Si en algun caso
// hace falta mas reglas, subir y volver a probar el verifier.
#define MAX_RULES 16

// Indices logicos de interfaz para identificar de donde viene un paquete
// y filtrar reglas que solo aplican a una iface concreta. Los valores los
// rellena user space en iface_indexes (ver mas abajo).
//   0 = enp6s0f0 (interna - lado cliente)
//   1 = eno1     (externa - lado internet)
//   2 = enp6s0f1 (TRex - generador, sin uso para filtrado)

// Estructura de regla. Cada paquete se compara contra cada regla activa;
// los flags has_* distinguen "wildcard" de "valor 0 que coincide solo con 0".
struct rule {
    __u8  enabled;       // 0 = ignorada, 1 = activa
    __u8  iface_idx;     // 0/1/2 (indice logico)
    __u8  protocol;      // 0=any, 6=TCP, 17=UDP, 1=ICMP
    __u8  action;        // 0=allow, 1=drop

    __u8  has_src_ip;
    __u8  has_dst_ip;
    __u8  has_src_port;
    __u8  has_dst_port;

    __be32 src_ip;       // network byte order
    __be32 dst_ip;
    __be16 src_port;     // network byte order
    __be16 dst_port;

    __u32 limit_pps;     // 0 = sin limite
    __u32 limit_bps;     // 0 = sin limite
    __u32 priority;      // informativo (orden ya viene dado por el array)
};

BPF_ARRAY(rules, struct rule, MAX_RULES);

// Bloqueo por CIDR (rangos enteros). Usa LPM Trie, la unica estructura
// eBPF que permite match por prefijo. Key:
//   prefixlen = numero de bits del prefijo (0-32)
//   ip[4]     = octetos en network byte order (big-endian)
// Valor: 1 = bloqueado. Lookup con prefixlen=32 devuelve el prefijo mas
// largo que cubra esa IP (longest prefix match).
struct cidr_key {
    __u32 prefixlen;
    __u8  ip[4];
};

BPF_LPM_TRIE(blocked_cidrs, struct cidr_key, __u8, 10000);

// Estado de rate-limit por (src_ip, iface). Ventana deslizante de 1 segundo:
// cada paquete que entra suma a packets/bytes; si supera el limite, drop.
// Cuando pasa 1s desde window_start_ns, se reinician los contadores.
struct rate_key {
    __u32 src_ip;
    __u32 iface_idx;
};

struct rate_val {
    __u64 packets;
    __u64 bytes;
    __u64 window_start_ns;
};

// PERCPU para evitar locks. Si en el futuro queremos sumar en user space,
// se itera sobre las CPUs y se acumulan los contadores.
BPF_PERCPU_HASH(rate_state, struct rate_key, struct rate_val, 16384);


// NAT
// IP interna -> IP externa (cliente saliendo a internet)
BPF_HASH(nat_in2out, u32, u32, 256);

// IP externa -> IP interna (respuesta de internet hacia cliente)
BPF_HASH(nat_out2in, u32, u32, 256);

// Indices fisicos del kernel (ifindex) por posicion logica.
// User space rellena:
//   iface_indexes[0] = ifindex de enp6s0f0
//   iface_indexes[1] = ifindex de eno1
//   iface_indexes[2] = ifindex de enp6s0f1 (opcional)
BPF_ARRAY(iface_indexes, u32, 3);


// Helpers de checksum
// Actualizacion incremental de checksum Internet (RFC 1624 ec. 3).
// Importante: u64 en la suma para no perder el carry que en u32 se
// sale por el bit 32 cuando sumamos varios valores de 32 bits.
static __always_inline void incr_check4(__sum16 *check,
                                        __be32 from,
                                        __be32 to)
{
    __u64 sum;

    sum  = ((__u32)*check) ^ 0xFFFF;
    sum += ((__u32)from) ^ 0xFFFFFFFF;
    sum += (__u32)to;

    sum = (sum & 0xFFFFFFFFULL) + (sum >> 32);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    *check = (__u16)(sum ^ 0xFFFF);
}

// Recalcula checksums IP y L4 (TCP/UDP) tras una reescritura de saddr/daddr.
// Recibe ctx para re-derivar data_end como puntero de paquete dentro del
// scope inlined: el verifier eBPF tiene reglas estrictas sobre bounds, y
// pasarle un puntero "void *" desde fuera puede no sobrevivir al inline.
// Devuelve 0 si OK, -1 si el paquete esta truncado.
static __always_inline int nat_recompute_checksums(struct xdp_md *ctx,
                                                   struct iphdr *ip,
                                                   __be32 old,
                                                   __be32 new)
{
    void *data_end = (void *)(long)ctx->data_end;

    incr_check4(&ip->check, old, new);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return -1;
        __u64 sum;
        sum  = ((__u32)tcp->check) ^ 0xFFFF;
        sum += ((__u32)old) ^ 0xFFFFFFFF;
        sum += (__u32)new;
        sum = (sum & 0xFFFFFFFFULL) + (sum >> 32);
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        tcp->check = (__u16)(sum ^ 0xFFFF);

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return -1;
        if (udp->check) {
            __u64 sum;
            sum  = ((__u32)udp->check) ^ 0xFFFF;
            sum += ((__u32)old) ^ 0xFFFFFFFF;
            sum += (__u32)new;
            sum = (sum & 0xFFFFFFFFULL) + (sum >> 32);
            sum = (sum & 0xFFFF) + (sum >> 16);
            sum = (sum & 0xFFFF) + (sum >> 16);
            udp->check = (__u16)(sum ^ 0xFFFF);
        }
    }
    return 0;
}


// Programa principal
int xdp_nat(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = (__u32)(data_end - data);

    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ihl < 5)
        return XDP_PASS;
    if ((void *)ip + (ip->ihl * 4) > data_end)
        return XDP_PASS;

    // Bloqueo CIDR global (threat intel, feeds AbuseIPDB, BGP prefixes...).
    // Si la IP origen cae en algun rango bloqueado, drop sin mas evaluacion.
    // Lookup con prefixlen=32: el LPM Trie devuelve el prefijo mas largo que
    // cubra esa IP (puede ser /32, /24, /22...).
    //
    // ip->saddr esta en network byte order (BE). Para que el LPM compare bit
    // a bit desde el MSB (primer octeto), copiamos los bytes en orden de
    // memoria sin interpretarlos como entero: usar shifts seria sensible al
    // endian de la maquina.
    {
        struct cidr_key ckey;
        ckey.prefixlen = 32;
        __u8 *saddr_bytes = (__u8 *)&ip->saddr;
        ckey.ip[0] = saddr_bytes[0];
        ckey.ip[1] = saddr_bytes[1];
        ckey.ip[2] = saddr_bytes[2];
        ckey.ip[3] = saddr_bytes[3];
        __u8 *blocked = blocked_cidrs.lookup(&ckey);
        if (blocked && *blocked)
            return XDP_DROP;
    }

    // Determinar el indice logico de la iface por la que entra el paquete.
    u32 ingress = ctx->ingress_ifindex;
    u32 k0 = 0, k1 = 1, k2 = 2;
    u32 *idx_internal = iface_indexes.lookup(&k0);
    u32 *idx_external = iface_indexes.lookup(&k1);
    u32 *idx_trex     = iface_indexes.lookup(&k2);

    __u8 my_iface = 0xFF;
    if (idx_internal && ingress == *idx_internal)      my_iface = 0;
    else if (idx_external && ingress == *idx_external) my_iface = 1;
    else if (idx_trex     && ingress == *idx_trex)     my_iface = 2;

    // Parsear puertos L4 (si aplica) una sola vez para reusar en el bucle.
    // Patron canonico para el verifier: comprobar > data_end y salir antes
    // de tocar los campos. Si el header L4 esta truncado, has_l4 = 0 y las
    // reglas que filtran por puerto no matchearan.
    __be16 sport = 0, dport = 0;
    __u8 has_l4 = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            goto after_l4;
        sport = tcp->source;
        dport = tcp->dest;
        has_l4 = 1;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            goto after_l4;
        sport = udp->source;
        dport = udp->dest;
        has_l4 = 1;
    }
after_l4:;

    // Bucle de filtrado: recorre el array en orden (las posiciones bajas
    // tienen mayor prioridad, user space las ordena al cargar). La primera
    // regla que matchea decide:
    //   - allow: deja pasar al NAT, no se evaluan mas reglas.
    //   - drop sin rate: descarta inmediato.
    //   - drop con rate-limit: solo descarta si supera el limite, sino sigue.
    if (my_iface != 0xFF) {

        #pragma clang loop unroll(full)
        for (u32 i = 0; i < MAX_RULES; i++) {

            struct rule *r = rules.lookup(&i);
            if (!r) continue;
            if (!r->enabled) continue;
            if (r->iface_idx != my_iface) continue;

            // Protocolo (0 = any)
            if (r->protocol && r->protocol != ip->protocol) continue;

            // IPs (cuando estan presentes en la regla)
            if (r->has_src_ip && r->src_ip != ip->saddr) continue;
            if (r->has_dst_ip && r->dst_ip != ip->daddr) continue;

            // Puertos (solo si el paquete tiene L4 parseado)
            if (r->has_src_port) {
                if (!has_l4) continue;
                if (r->src_port != sport) continue;
            }
            if (r->has_dst_port) {
                if (!has_l4) continue;
                if (r->dst_port != dport) continue;
            }

            // Match: aplicar accion o rate-limit.
            __u8 has_rate = (r->limit_pps || r->limit_bps);

            if (has_rate) {
                // Acumular contadores en la ventana actual y comprobar
                struct rate_key rk = {};
                rk.src_ip    = ip->saddr;
                rk.iface_idx = my_iface;

                __u64 now = bpf_ktime_get_ns();

                struct rate_val *rv = rate_state.lookup(&rk);
                if (!rv) {
                    struct rate_val nv = {};
                    nv.packets = 1;
                    nv.bytes   = pkt_len;
                    nv.window_start_ns = now;
                    rate_state.update(&rk, &nv);
                    // Primer paquete dentro de la ventana: nunca supera
                } else {
                    if (now - rv->window_start_ns > 1000000000ULL) {
                        rv->packets = 1;
                        rv->bytes   = pkt_len;
                        rv->window_start_ns = now;
                    } else {
                        rv->packets += 1;
                        rv->bytes   += pkt_len;
                    }
                    if (r->limit_pps && rv->packets > r->limit_pps)
                        return XDP_DROP;
                    if (r->limit_bps && rv->bytes   > r->limit_bps)
                        return XDP_DROP;
                }
                // Si la regla es solo rate-limit y no se ha superado, salir
                // del bucle: no aplican mas reglas aunque sigan matcheando.
                break;
            }

            // Sin rate-limit: la accion se aplica directamente
            if (r->action == 1) {  // drop
                return XDP_DROP;
            }
            // allow: dejar pasar al NAT
            break;
        }
    }


    // Path de benchmark: trafico inyectado por TRex en enp6s0f1. La politica
    // por defecto es DROP, aceptamos tres excepciones:
    //   (a) Hacia la propia IP de ORION en esta iface (10.0.3.2): XDP_PASS
    //       al stack. Permite ping, iperf3, SSH y cualquier servicio local
    //       expuesto al lado TRex para diagnostico.
    //   (b) Hacia una IP publica del NAT (dst en nat_out2in): reescribimos
    //       a la IP privada y REDIRECT a enp6s0f0. Mide NAT+REDIRECT a
    //       wire-speed (lo que vera el cliente real al responderle Internet)
    //       sin pasar por el stack del kernel.
    //   (c) Hacia 10.0.2.0/24 directo: REDIRECT a enp6s0f0 sin NAT. Mide el
    //       REDIRECT puro.
    // Resto: XDP_DROP, enp6s0f1 actua como "puerto cerrado" en la maqueta.
    if (my_iface == 2) {
        // (a) Trafico a la propia IP de ORION (10.0.3.2): al stack
        if (ip->daddr == bpf_htonl(0x0A000302) /* 10.0.3.2 */) {
            return XDP_PASS;
        }

        // ifindex de enp6s0f0 (destino del redirect)
        u32 k_internal = 0;
        u32 *idx_internal_redir = iface_indexes.lookup(&k_internal);
        if (!idx_internal_redir)
            return XDP_DROP;

        // (b) NAT entrante + REDIRECT (dst es IP publica del NAT)
        u32 *new_daddr = nat_out2in.lookup(&ip->daddr);
        if (new_daddr) {
            __be32 old = ip->daddr;
            __be32 new = *new_daddr;
            ip->daddr = new;
            if (nat_recompute_checksums(ctx, ip, old, new) < 0)
                return XDP_DROP;
            return bpf_redirect(*idx_internal_redir, 0);
        }

        // (c) REDIRECT directo a 10.0.2.0/24 (sin NAT)
        if ((ip->daddr & bpf_htonl(0xFFFFFF00)) == bpf_htonl(0x0A000200)) {
            return bpf_redirect(*idx_internal_redir, 0);
        }

        // (d) Resto: drop
        return XDP_DROP;
    }

    if (my_iface == 0xFF)
        return XDP_PASS;  // iface desconocida

    __be32 old = 0;
    __be32 new = 0;
    int matched = 0;

    if (my_iface == 0) {
        // Saliente: cliente -> internet. Reescribir saddr.
        // Excepcion: trafico cuyo destino esta en la propia subred del cliente
        // (10.0.2.0/24) no debe NAT-earse, sino se rompen pings al gateway.
        if ((ip->daddr & bpf_htonl(0xFFFFFF00)) == bpf_htonl(0x0A000200))
            return XDP_PASS;

        u32 *new_saddr = nat_in2out.lookup(&ip->saddr);
        if (!new_saddr)
            return XDP_PASS;

        old = ip->saddr;
        new = *new_saddr;
        ip->saddr = new;
        matched = 1;

    } else if (my_iface == 1) {
        // Entrante: internet -> cliente. Reescribir daddr.
        u32 *new_daddr = nat_out2in.lookup(&ip->daddr);
        if (!new_daddr)
            return XDP_PASS;

        old = ip->daddr;
        new = *new_daddr;
        ip->daddr = new;
        matched = 1;
    }

    if (!matched)
        return XDP_PASS;

    if (nat_recompute_checksums(ctx, ip, old, new) < 0)
        return XDP_PASS;

    return XDP_PASS;
}
