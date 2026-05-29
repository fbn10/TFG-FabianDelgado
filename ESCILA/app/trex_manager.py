# Gestor de comunicacion con TRex para ESCILA.
#
# Esta clase envuelve el cliente Python de TRex (STLClient) y la invocacion
# del script escila_trex.sh, ofreciendo al servidor Flask una interfaz
# sencilla con conexion asincrona, control de trafico y recoleccion de
# estadisticas.

import sys
import os
import time
import subprocess
import threading

os.environ['TREX_EXT_LIBS'] = '/home/minerva/Escritorio/TFG_Fabian/ESCILA/v3.08/external_libs'
sys.path.insert(0, '/home/minerva/Escritorio/TFG_Fabian/ESCILA/v3.08/automation/trex_control_plane/interactive')

ESCILA_TREX_SCRIPT = '/home/minerva/Escritorio/TFG_Fabian/ESCILA/escila_trex.sh'

from trex.stl.api import (
    STLClient, STLStream, STLPktBuilder,
    STLTXCont, STLTXSingleBurst
)
from scapy.layers.l2   import Ether, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns  import DNS, DNSQR
from scapy.packet      import Raw

candado = threading.Lock()


def seguro_int(valor, defecto=0):
    """Convierte un valor a entero de forma defensiva. Si el valor es None,
    una cadena vacia o no convertible, devuelve el valor por defecto."""
    try:
        return int(valor) if valor not in (None, '', ' ') else defecto
    except (ValueError, TypeError):
        return defecto


def seguro_float(valor, defecto=0.0):
    """Variante de seguro_int para floats."""
    try:
        return float(valor) if valor not in (None, '', ' ') else defecto
    except (ValueError, TypeError):
        return defecto


class GestorTRex:

    def __init__(self):
        self.cliente         = None
        self.conectado       = False
        self.trafico_activo  = False
        self.streams_activos = []
        self.modo_dpdk       = False
        self.max_mbps_sesion = 0.0
        # Maquina de estados que el frontend consulta por polling.
        # Valores posibles: desconectado, conectando, conectado,
        # desconectando, error.
        self.estado          = 'desconectado'
        self.ultimo_error    = ''


    # Conexion con TRex.

    def _ejecutar_script(self, accion, timeout=45):
        """Ejecuta escila_trex.sh con sudo en modo no interactivo. Devuelve
        una tupla (exito, salida_combinada)."""
        try:
            res = subprocess.run(
                ['sudo', '-n', ESCILA_TREX_SCRIPT, accion],
                capture_output=True, text=True, timeout=timeout
            )
            ok = (res.returncode == 0)
            salida = (res.stdout or '') + (res.stderr or '')
            return ok, salida.strip()
        except subprocess.TimeoutExpired:
            return False, f'Timeout ejecutando {accion}'
        except Exception as e:
            return False, f'Error ejecutando {accion}: {str(e)}'

    def conectar(self):
        """Inicia la conexion en un hilo de fondo y devuelve inmediatamente,
        evitando que el navegador agote su timeout durante el arranque de
        TRex (que puede tardar entre 15 y 30 segundos)."""
        if self.estado == 'conectando':
            return {'exito': True, 'mensaje': 'Arrancando TRex, espera unos segundos'}
        if self.estado == 'conectado':
            return {'exito': True, 'mensaje': 'Ya conectado'}

        self.estado = 'conectando'
        self.ultimo_error = ''
        threading.Thread(target=self._conectar_async, daemon=True).start()
        return {'exito': True, 'mensaje': 'Arrancando TRex en DPDK (15-30 segundos)'}

    def _conectar_async(self):
        """Trabajo real de conexion ejecutado en segundo plano."""
        try:
            ok, salida = self._ejecutar_script('start', timeout=90)
            if not ok:
                self.estado = 'error'
                self.ultimo_error = salida[-200:]
                return

            time.sleep(2)

            with candado:
                self.cliente = STLClient(server='127.0.0.1')
                self.cliente.connect()
                self.cliente.acquire(force=True)
                self.cliente.reset()
                self.conectado = True
                try:
                    info = self.cliente.get_server_system_info()
                    self.modo_dpdk = 'software' not in str(info).lower()
                except Exception:
                    self.modo_dpdk = True
            self.estado = 'conectado'
        except Exception as e:
            self.estado = 'error'
            self.ultimo_error = str(e)
            self.conectado = False

    def desconectar(self):
        """Inicia la desconexion en segundo plano."""
        if self.estado == 'desconectando':
            return {'exito': True, 'mensaje': 'Desconectando, espera unos segundos'}
        if self.estado == 'desconectado':
            return {'exito': True, 'mensaje': 'Ya desconectado'}

        self.estado = 'desconectando'
        threading.Thread(target=self._desconectar_async, daemon=True).start()
        return {'exito': True, 'mensaje': 'Parando TRex y recuperando las NICs'}

    def _desconectar_async(self):
        try:
            with candado:
                if self.cliente and self.conectado:
                    if self.trafico_activo:
                        try: self.cliente.stop(ports=[0])
                        except Exception: pass
                    try: self.cliente.disconnect()
                    except Exception: pass
                self.conectado       = False
                self.trafico_activo  = False
                self.streams_activos = []
                self.cliente         = None

            ok, salida = self._ejecutar_script('stop', timeout=45)
            if not ok:
                self.ultimo_error = salida[-200:]
            self.estado = 'desconectado'
        except Exception as e:
            self.estado = 'error'
            self.ultimo_error = str(e)

    def ping(self):
        """Comprueba que el cliente sigue conectado al servidor TRex."""
        try:
            if not self.cliente or not self.conectado:
                return False
            self.cliente.get_stats()
            return True
        except Exception:
            self.conectado      = False
            self.trafico_activo = False
            return False


    # Construccion de paquetes (capas 2 a 7).

    def construir_payload_l7(self, config):
        """Genera el payload de capa 7 segun la opcion elegida en el editor
        de streams. Si no se especifica, rellena el paquete hasta el tamano
        indicado."""
        tipo = config.get('tipo_l7', 'ninguno')
        tam  = seguro_int(config.get('tam_paquete'), 64)

        if tipo == 'http_get':
            host   = config.get('http_host',   'www.ejemplo.com') or 'www.ejemplo.com'
            ruta   = config.get('http_ruta',   '/') or '/'
            agente = config.get('http_agente', 'ESCILA/1.0') or 'ESCILA/1.0'
            return Raw(load=(
                f"GET {ruta} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {agente}\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode())

        elif tipo == 'http_post':
            host   = config.get('http_host',   'www.ejemplo.com') or 'www.ejemplo.com'
            ruta   = config.get('http_ruta',   '/') or '/'
            cuerpo = config.get('http_cuerpo', 'dato=valor&test=escila') or 'dato=valor'
            return Raw(load=(
                f"POST {ruta} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(cuerpo)}\r\n\r\n"
                f"{cuerpo}"
            ).encode())

        elif tipo == 'dns':
            dominio = config.get('dns_dominio', 'ejemplo.com') or 'ejemplo.com'
            return DNS(rd=1, qd=DNSQR(qname=dominio))

        elif tipo == 'texto':
            texto = config.get('payload_texto', 'ESCILA-TEST') or 'ESCILA-TEST'
            return Raw(load=texto.encode())

        elif tipo == 'hex':
            hex_str = (config.get('payload_hex', 'DEADBEEF') or 'DEADBEEF').replace(' ', '')
            try:
                return Raw(load=bytes.fromhex(hex_str))
            except Exception:
                return Raw(load=b'ESCILA')

        elif tipo == 'patron':
            patron = config.get('payload_patron', 'AB') or 'AB'
            datos  = (patron * (tam // max(len(patron), 1) + 1))[:tam]
            return Raw(load=datos.encode('latin-1', errors='replace'))

        elif tipo == 'tls':
            # TLS Client Hello simulado (no autentico, util para inspeccion).
            tls_hello = bytes.fromhex('160301009f010000b903031000') + os.urandom(28)
            return Raw(load=tls_hello)

        elif tipo == 'raw_hex':
            hex_str = (config.get('raw_hex', '') or '').replace(' ', '').replace('\n', '')
            try:
                return Raw(load=bytes.fromhex(hex_str))
            except Exception:
                return Raw(load=b'\x00' * max(0, tam - 42))

        else:
            return Raw(load=b'A' * max(0, tam - 42))

    def construir_paquete(self, config):
        """Construye el paquete completo capa a capa a partir de la
        configuracion recibida del editor de streams."""
        # Capa 2: Ethernet.
        pkt = Ether(
            src=config.get('mac_origen',  '00:00:00:00:00:01') or '00:00:00:00:00:01',
            dst=config.get('mac_destino', 'ff:ff:ff:ff:ff:ff') or 'ff:ff:ff:ff:ff:ff'
        )

        # Etiqueta VLAN opcional.
        vlan = seguro_int(config.get('vlan_id'), 0)
        if vlan > 0:
            pkt = pkt / Dot1Q(vlan=vlan)

        # Capa 3: IPv4.
        pkt = pkt / IP(
            src=config.get('ip_origen',  '1.1.1.1') or '1.1.1.1',
            dst=config.get('ip_destino', '2.2.2.2') or '2.2.2.2',
            ttl=seguro_int(config.get('ttl'), 64),
            tos=seguro_int(config.get('tos'), 0)
        )

        # Capa 4: protocolo de transporte.
        proto = (config.get('protocolo', 'UDP') or 'UDP').upper()

        if proto == 'TCP':
            pkt = pkt / TCP(
                sport=seguro_int(config.get('puerto_origen'),  1024),
                dport=seguro_int(config.get('puerto_destino'), 80),
                flags=config.get('flags_tcp', 'S') or 'S'
            )
        elif proto == 'UDP':
            pkt = pkt / UDP(
                sport=seguro_int(config.get('puerto_origen'),  1024),
                dport=seguro_int(config.get('puerto_destino'), 80)
            )
        elif proto == 'ICMP':
            pkt = pkt / ICMP(
                type=seguro_int(config.get('tipo_icmp'),   8),
                code=seguro_int(config.get('codigo_icmp'), 0)
            )

        # Payload de capa 5 a 7.
        pkt = pkt / self.construir_payload_l7(config)
        return pkt

    def construir_stream(self, config, indice=0):
        """Traduce la configuracion del editor a un objeto STLStream listo
        para inyectar en TRex."""
        paquete  = self.construir_paquete(config)
        modo_t   = config.get('modo_tasa', 'pps') or 'pps'
        valor    = seguro_float(config.get('valor_tasa'), 1000.0)
        num_pkts = seguro_int(config.get('num_paquetes'), 0)

        if valor <= 0:
            valor = 1000.0

        if num_pkts > 0:
            modo = STLTXSingleBurst(pps=valor, total_pkts=num_pkts)
        else:
            if modo_t == 'pps':
                modo = STLTXCont(pps=valor)
            elif modo_t == 'bps':
                modo = STLTXCont(bps_L1=valor)
            elif modo_t == 'gbps':
                modo = STLTXCont(bps_L1=valor * 1e9)
            elif modo_t == 'porcentaje':
                modo = STLTXCont(percentage=min(valor, 100.0))
            else:
                modo = STLTXCont(pps=valor)

        return STLStream(
            name=f'stream_{indice}',
            packet=STLPktBuilder(pkt=paquete),
            mode=modo
        )


    # Control de trafico.

    def iniciar_trafico(self, lista_streams):
        """Construye los streams a partir de la lista recibida y los arranca
        en el puerto 0."""
        try:
            with candado:
                if not self.conectado:
                    return {'exito': False, 'mensaje': 'No conectado. Pulsa Conectar primero'}
                self.cliente.remove_all_streams()
                streams = [self.construir_stream(c, i) for i, c in enumerate(lista_streams)]
                self.cliente.add_streams(streams, ports=[0])
                self.cliente.start(ports=[0], force=True)
                self.trafico_activo  = True
                self.streams_activos = lista_streams
            return {'exito': True, 'mensaje': f'{len(streams)} stream(s) iniciados correctamente'}
        except Exception as e:
            self.trafico_activo = False
            return {'exito': False, 'mensaje': f'Error al iniciar: {str(e)}'}

    def parar_trafico(self):
        try:
            with candado:
                if not self.conectado:
                    return {'exito': False, 'mensaje': 'No conectado'}
                self.cliente.stop(ports=[0])
                self.cliente.remove_all_streams()
                self.trafico_activo  = False
                self.streams_activos = []
            return {'exito': True, 'mensaje': 'Trafico parado correctamente'}
        except Exception as e:
            return {'exito': False, 'mensaje': f'Error: {str(e)}'}

    def resetear_puertos(self):
        try:
            with candado:
                if not self.conectado:
                    return {'exito': False, 'mensaje': 'No conectado'}
                self.cliente.reset()
                self.trafico_activo  = False
                self.streams_activos = []
            return {'exito': True, 'mensaje': 'Puertos reseteados correctamente'}
        except Exception as e:
            return {'exito': False, 'mensaje': f'Error: {str(e)}'}


    # Estadisticas.

    def obtener_estadisticas(self):
        """Lee las estadisticas del puerto 0 (TX) y del puerto 1 (RX) y
        construye el diccionario que consume el dashboard."""
        try:
            if not self.conectado or not self.cliente:
                return self._stats_vacias()
            if not self.ping():
                return self._stats_vacias()
            with candado:
                stats = self.cliente.get_stats()
            p0 = stats.get(0, {})
            p1 = stats.get(1, {})
            gl = stats.get('global', {})

            tx_mbps = round(p0.get('tx_bps_L1', 0) / 1e6, 3)

            # Actualizamos el pico maximo alcanzado durante la sesion.
            if tx_mbps > self.max_mbps_sesion:
                self.max_mbps_sesion = tx_mbps

            # Porcentaje sobre el pico real, sin limite artificial.
            pct_uso = round((tx_mbps / self.max_mbps_sesion) * 100, 1) if self.max_mbps_sesion > 0 else 0

            return {
                'exito'          : True,
                'conectado'      : self.conectado,
                'estado'         : self.estado,
                'ultimo_error'   : self.ultimo_error,
                'trafico_activo' : self.trafico_activo,
                'num_streams'    : len(self.streams_activos),
                'modo_dpdk'      : self.modo_dpdk,
                'max_mbps_sesion': round(self.max_mbps_sesion, 3),
                'pct_uso'        : pct_uso,
                'tx_pps'         : round(p0.get('tx_pps',    0), 2),
                'tx_mbps'        : tx_mbps,
                'tx_gbps'        : round(p0.get('tx_bps_L1', 0) / 1e9, 6),
                'tx_paquetes'    : int(p0.get('opackets', 0)),
                'tx_bytes'       : int(p0.get('obytes',   0)),
                'rx_pps'         : round(p1.get('rx_pps',    0), 2),
                'rx_mbps'        : round(p1.get('rx_bps_L1', 0) / 1e6, 3),
                'rx_gbps'        : round(p1.get('rx_bps_L1', 0) / 1e9, 6),
                'rx_paquetes'    : int(p1.get('ipackets', 0)),
                'drops'          : int(gl.get('drops',      0)),
                'errores'        : int(gl.get('queue_full', 0)),
            }
        except Exception:
            self.conectado      = False
            self.trafico_activo = False
            return self._stats_vacias()

    def _stats_vacias(self):
        """Diccionario por defecto cuando no hay datos disponibles."""
        return {
            'exito': True, 'conectado': False, 'trafico_activo': False,
            'estado': self.estado, 'ultimo_error': self.ultimo_error,
            'num_streams': 0, 'modo_dpdk': False,
            'max_mbps_sesion': 0, 'pct_uso': 0,
            'tx_pps': 0, 'tx_mbps': 0, 'tx_gbps': 0,
            'tx_paquetes': 0, 'tx_bytes': 0,
            'rx_pps': 0, 'rx_mbps': 0, 'rx_gbps': 0,
            'rx_paquetes': 0, 'drops': 0, 'errores': 0,
        }


# Instancia global usada por el servidor Flask.
gestor = GestorTRex()
