#!/bin/bash
#
# Gestor del ciclo DPDK de TRex para ESCILA.
#
# Este script automatiza todo lo que requiere privilegios de root:
# carga del modulo vfio_pci, reserva de hugepages, bind de las NICs entre
# el driver del kernel (ixgbe) y vfio-pci, y arranque o parada del proceso
# t-rex-64 en segundo plano.
#
# Subcomandos:
#   start   Prepara el entorno DPDK y arranca TRex.
#   stop    Detiene TRex y devuelve las NICs al kernel.
#   status  Muestra si TRex esta corriendo y su PID.
#

TREX_DIR="/home/minerva/Escritorio/TFG_Fabian/ESCILA/v3.08"
TREX_YAML="$TREX_DIR/cfg/trex_direct.yaml"
TREX_PID_FILE="/var/run/escila_trex.pid"
TREX_LOG="/var/log/escila_trex.log"
INTERFACES_PCI=("06:00.0" "06:00.1")
KERNEL_DRIVER="ixgbe"

start_trex() {
    echo "[START] Iniciando TRex en modo DPDK."

    # Si TRex ya esta corriendo no hacemos nada (operacion idempotente).
    if [ -f $TREX_PID_FILE ] && kill -0 $(cat $TREX_PID_FILE) 2>/dev/null; then
        echo "[START] TRex ya esta corriendo (pid=$(cat $TREX_PID_FILE)), nada que hacer."
        return 0
    fi
    if pgrep -f "_t-rex-64" > /dev/null; then
        TREX_PID=$(pgrep -f "_t-rex-64" | head -1)
        echo $TREX_PID > $TREX_PID_FILE
        echo "[START] Detectado proceso TRex huerfano (pid=$TREX_PID), se adopta."
        return 0
    fi

    # Cargar el modulo vfio_pci si todavia no esta en el kernel.
    if ! lsmod | grep -q "^vfio_pci"; then
        modprobe vfio_pci || { echo "ERROR: no se pudo cargar vfio_pci"; return 1; }
    fi

    # Reservar 512 paginas de 2 MiB (1 GiB) para DPDK si no hay suficientes.
    HP=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
    if [ "$HP" -lt 512 ]; then
        echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
    fi

    # Ceder las NICs a vfio-pci. Se hace primero unbind y luego bind para
    # evitar que dpdk_nic_bind.py falle si ya estaban ligadas a otro driver.
    python3 $TREX_DIR/dpdk_nic_bind.py --unbind ${INTERFACES_PCI[@]} 2>&1 | tee -a $TREX_LOG
    python3 $TREX_DIR/dpdk_nic_bind.py --bind=vfio-pci ${INTERFACES_PCI[@]} 2>&1 | tee -a $TREX_LOG

    # Al ceder las NICs al espacio de usuario, la ruta por defecto puede
    # desaparecer. Si eno1 no tiene ruta, pedimos una IP por DHCP para
    # conservar acceso a la red de gestion.
    if ! ip route show default | grep -q "dev eno1"; then
        dhclient eno1 2>/dev/null &
    fi

    # Arrancar TRex en segundo plano. El parametro -i activa el modo
    # servidor STL (interactivo), necesario para que la aplicacion pueda
    # conectarse mediante STLClient.
    cd $TREX_DIR
    nohup ./t-rex-64 -i -c 4 --cfg $TREX_YAML > $TREX_LOG 2>&1 &
    TREX_PID=$!
    echo $TREX_PID > $TREX_PID_FILE

    # Esperar hasta 30 segundos a que TRex abra el puerto 4501.
    for i in {1..30}; do
        if ss -ln 2>/dev/null | grep -q :4501; then
            echo "[START] TRex listo (pid=$TREX_PID)."
            return 0
        fi
        sleep 1
    done
    echo "[START] ERROR: TRex no arranco en 30 segundos. Revisar log: $TREX_LOG"
    return 1
}

stop_trex() {
    echo "[STOP] Parando TRex y devolviendo las NICs al kernel."

    # Terminar el proceso TRex de forma ordenada y, si no responde, forzar.
    if [ -f $TREX_PID_FILE ]; then
        PID=$(cat $TREX_PID_FILE)
        kill -TERM $PID 2>/dev/null
        sleep 2
        kill -KILL $PID 2>/dev/null
        rm -f $TREX_PID_FILE
    fi
    pkill -f "_t-rex-64" 2>/dev/null
    sleep 2

    # Asegurar que ixgbe esta cargado y devolver las NICs a ese driver.
    modprobe $KERNEL_DRIVER 2>/dev/null
    python3 $TREX_DIR/dpdk_nic_bind.py --unbind ${INTERFACES_PCI[@]} 2>&1 | tee -a $TREX_LOG
    python3 $TREX_DIR/dpdk_nic_bind.py --bind=$KERNEL_DRIVER ${INTERFACES_PCI[@]} 2>&1 | tee -a $TREX_LOG

    # Levantar las interfaces y reaplicar netplan para restaurar las IPs.
    sleep 1
    ip link set dev enp6s0f0 up 2>/dev/null
    ip link set dev enp6s0f1 up 2>/dev/null
    netplan apply 2>&1 | tee -a $TREX_LOG

    echo "[STOP] TRex parado, NICs devueltas a $KERNEL_DRIVER."
    return 0
}

status_trex() {
    if [ -f $TREX_PID_FILE ] && kill -0 $(cat $TREX_PID_FILE) 2>/dev/null; then
        echo "running pid=$(cat $TREX_PID_FILE)"
        return 0
    fi
    echo "stopped"
    return 1
}

case "$1" in
    start)  start_trex  ;;
    stop)   stop_trex   ;;
    status) status_trex ;;
    *)      echo "Uso: $0 {start|stop|status}"; exit 1 ;;
esac
