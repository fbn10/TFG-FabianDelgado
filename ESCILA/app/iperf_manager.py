# Gestor de iperf3 (cliente o servidor) para ESCILA.
#
# Esta clase envuelve al binario iperf3 con subprocess.Popen, lee su salida
# linea a linea en un hilo de fondo, la parsea con expresiones regulares y
# expone las metricas (throughput, transferido, retransmisiones, jitter y
# datagramas perdidos) al servidor Flask.

import subprocess
import threading
import shlex
import time
import json
import re


class GestorIperf:

    def __init__(self):
        self.proceso        = None
        self.salida         = []     # Buffer circular con la salida cruda.
        self.salida_max     = 500
        self.activo         = False
        self.modo           = None   # 'cliente' o 'servidor'
        self.comando        = ''
        self.candado        = threading.Lock()
        self.hilo_lector    = None
        # Metricas en vivo correspondientes al ultimo intervalo parseado.
        self.bps_actual     = 0.0    # Bits por segundo del intervalo actual.
        self.transferido    = 0.0    # Bytes totales acumulados durante el test.
        self.retrans        = 0
        self.intervalo_act  = ''
        self.es_resumen     = False
        self.historial_bps  = []     # Ultimos N valores para la grafica.
        self.historial_max  = 60
        self.streams_mult   = False  # True si el test usa varios streams (-P > 1).
        self.intervalos     = []     # Historial estructurado de intervalos.
        self.intervalos_max = 200
        self.perdidos       = 0      # Datagramas UDP perdidos (resumen final).
        self.total_dg       = 0      # Datagramas UDP totales (resumen final).
        self.jitter         = 0.0    # Jitter UDP en milisegundos.


    # Interfaces de red disponibles.

    def listar_interfaces(self):
        """Devuelve una lista de interfaces con sus IPv4 a partir de
        'ip -j -4 addr'. Sirve para poblar el selector de bind del frontend."""
        interfaces = []
        try:
            res = subprocess.run(['ip', '-j', '-4', 'addr'],
                                 capture_output=True, text=True, timeout=5)
            datos = json.loads(res.stdout)
            for ifx in datos:
                nombre = ifx.get('ifname', '')
                if nombre == 'lo':
                    continue
                for a in ifx.get('addr_info', []):
                    if a.get('family') == 'inet':
                        interfaces.append({'interfaz': nombre, 'ip': a['local']})
        except Exception:
            pass
        return interfaces


    # Construccion del comando.

    def _construir_args(self, cfg):
        """Traduce la configuracion recibida del frontend a la lista de
        argumentos que se pasa al binario iperf3."""
        args = ['iperf3']

        modo = cfg.get('modo', 'cliente')
        if modo == 'servidor':
            args.append('-s')
            if cfg.get('puerto'):
                args += ['-p', str(int(cfg['puerto']))]
            if cfg.get('bind_ip'):
                args += ['-B', cfg['bind_ip']]
        else:
            host = cfg.get('host', '')
            if not host:
                raise ValueError('Falta la IP destino (-c)')
            args += ['-c', host]

            if cfg.get('puerto'):
                args += ['-p', str(int(cfg['puerto']))]
            if cfg.get('duracion'):
                # iperf3 admite como maximo 86400 segundos (24 horas).
                d = int(cfg['duracion'])
                if d > 86400: d = 86400
                args += ['-t', str(d)]
            if cfg.get('intervalo'):
                args += ['-i', str(float(cfg['intervalo']))]
            if cfg.get('streams'):
                args += ['-P', str(int(cfg['streams']))]
            if cfg.get('udp'):
                args.append('-u')
            if cfg.get('tam_buffer'):
                args += ['-l', str(cfg['tam_buffer'])]
            if cfg.get('ancho_banda'):
                args += ['-b', str(cfg['ancho_banda'])]
            if cfg.get('reverse'):
                args.append('-R')
            if cfg.get('bind_ip'):
                args += ['-B', cfg['bind_ip']]

        return args


    # Arranque del proceso iperf3.

    def iniciar(self, cfg):
        """Lanza iperf3 como subproceso, redirige su salida a una tuberia
        y arranca el hilo lector que parsea cada linea."""
        with self.candado:
            if self.activo:
                return {'exito': False, 'mensaje': 'Ya hay un iperf en ejecucion'}

            try:
                args = self._construir_args(cfg)
            except Exception as e:
                return {'exito': False, 'mensaje': str(e)}

            self.salida = []
            self.comando = ' '.join(shlex.quote(a) for a in args)
            self.modo = cfg.get('modo', 'cliente')
            # Reseteamos las metricas para que el nuevo test empiece desde cero.
            self.bps_actual = 0.0
            self.transferido = 0.0
            self.retrans = 0
            self.intervalo_act = ''
            self.es_resumen = False
            self.historial_bps = []
            self.intervalos = []
            self.perdidos = 0
            self.total_dg = 0
            self.jitter = 0.0
            try:
                self.streams_mult = int(cfg.get('streams') or 1) > 1
            except Exception:
                self.streams_mult = False

            try:
                self.proceso = subprocess.Popen(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=1,
                    universal_newlines=True
                )
            except FileNotFoundError:
                return {'exito': False, 'mensaje': 'iperf3 no esta instalado'}
            except Exception as e:
                return {'exito': False, 'mensaje': f'Error lanzando iperf3: {str(e)}'}

            self.activo = True
            self.hilo_lector = threading.Thread(target=self._leer_salida, daemon=True)
            self.hilo_lector.start()

            return {'exito': True, 'mensaje': f'iperf3 iniciado: {self.comando}'}


    # Parser de la salida de iperf3.
    #
    # La expresion regular contempla los dos formatos principales:
    #   [  5]   0.00-1.00   sec   115 MBytes   963 Mbits/sec   0  1.41 MBytes
    #   [SUM]   0.00-1.00   sec   230 MBytes   1.92 Gbits/sec
    # y los campos adicionales propios de UDP (jitter + perdidos/total).
    _RE_LINEA = re.compile(
        r'\[\s*(?P<id>\d+|SUM)\]\s+'
        r'(?P<ini>\d+\.?\d*)-(?P<fin>\d+\.?\d*)\s+sec\s+'
        r'(?P<transfer>\d+\.?\d*)\s+(?P<unit_t>[KMG]?)Bytes\s+'
        r'(?P<bitrate>\d+\.?\d*)\s+(?P<unit_b>[KMG]?)bits/sec'
        r'(?:\s+(?P<jitter>\d+\.?\d*)\s+ms\s+(?P<lost>\d+)/(?P<total>\d+))?'  # UDP: jitter y datagramas perdidos.
        r'(?:\s+(?P<retr>\d+))?'                                              # TCP retr o datagramas de intervalo UDP.
        r'(?:\s+(?P<cwnd>\d+\.?\d*)\s+(?P<unit_c>[KMG]?)Bytes)?'              # TCP cwnd.
    )

    _MUL_BYTES = {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12}
    _MUL_BITS  = {'': 1, 'K': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12}

    def _parsear_linea(self, linea):
        """Extrae las metricas de una linea de salida y actualiza el estado.
        Devuelve True si la linea encajaba con el formato esperado."""
        m = self._RE_LINEA.search(linea)
        if not m:
            return False
        ident = m.group('id')
        es_sum = (ident == 'SUM')
        # Cuando se usan varios streams paralelos (-P > 1), iperf3 reporta una
        # linea por stream mas una linea agregada [SUM]. Para no contar dos
        # veces, ignoramos las lineas individuales y nos quedamos con la suma.
        if self.streams_mult and not es_sum:
            return False

        bps = float(m.group('bitrate')) * self._MUL_BITS[m.group('unit_b')]
        bytes_t = float(m.group('transfer')) * self._MUL_BYTES[m.group('unit_t')]
        retr = int(m.group('retr') or 0)
        cwnd_b = 0.0
        if m.group('cwnd'):
            cwnd_b = float(m.group('cwnd')) * self._MUL_BYTES[m.group('unit_c') or '']
        # Campos especificos de UDP (jitter y datagramas perdidos/totales).
        jitter = float(m.group('jitter')) if m.group('jitter') else 0.0
        lost   = int(m.group('lost'))  if m.group('lost')  else 0
        total  = int(m.group('total')) if m.group('total') else 0
        es_resumen = 'sender' in linea.lower() or 'receiver' in linea.lower()
        tipo = 'receiver' if 'receiver' in linea.lower() else ('sender' if 'sender' in linea.lower() else 'intervalo')
        intervalo_str = f"{m.group('ini')}-{m.group('fin')}"

        with self.candado:
            self.bps_actual = bps
            self.intervalo_act = f"{intervalo_str}s"
            self.es_resumen = es_resumen

            if es_resumen:
                # Las lineas de resumen llevan ya el total: sobrescriben.
                self.transferido = bytes_t
                self.retrans = retr
            else:
                # Las lineas de intervalo se acumulan.
                self.transferido += bytes_t
                self.retrans += retr
                self.historial_bps.append(bps)
                if len(self.historial_bps) > self.historial_max:
                    self.historial_bps = self.historial_bps[-self.historial_max:]

            if lost or total:
                self.perdidos = lost
                self.total_dg = total
                self.jitter   = jitter

            # Guardamos el intervalo completo en un historial estructurado.
            self.intervalos.append({
                'ts'        : time.time(),
                'tipo'      : tipo,
                'intervalo' : intervalo_str,
                'transfer'  : bytes_t,
                'bitrate'   : bps,
                'retr'      : retr,
                'cwnd'      : cwnd_b,
                'jitter'    : jitter,
                'lost'      : lost,
                'total'     : total,
            })
            if len(self.intervalos) > self.intervalos_max:
                self.intervalos = self.intervalos[-self.intervalos_max:]
        return True

    def _leer_salida(self):
        """Hilo lector: consume la salida del subproceso linea a linea."""
        try:
            for linea in self.proceso.stdout:
                linea = linea.rstrip()
                with self.candado:
                    self.salida.append(linea)
                    if len(self.salida) > self.salida_max:
                        self.salida = self.salida[-self.salida_max:]
                self._parsear_linea(linea)
        except Exception:
            pass
        finally:
            with self.candado:
                self.activo = False
                # Importante: no reseteamos bps_actual ni transferido aqui.
                # Asi la GUI mantiene visibles las metricas finales del test
                # cuando el proceso ya ha terminado.


    # Parada del proceso.

    def parar(self):
        with self.candado:
            if not self.activo or not self.proceso:
                return {'exito': False, 'mensaje': 'No hay iperf activo'}
            try:
                self.proceso.terminate()
                try: self.proceso.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proceso.kill()
                self.activo = False
                return {'exito': True, 'mensaje': 'iperf3 parado'}
            except Exception as e:
                return {'exito': False, 'mensaje': f'Error parando: {str(e)}'}


    # Estado actual para el frontend.

    def obtener_estado(self):
        """Snapshot completo del estado actual del gestor. El frontend lo
        consulta por polling para alimentar tarjetas, grafica y tabla."""
        with self.candado:
            return {
                'activo'        : self.activo,
                'modo'          : self.modo,
                'comando'       : self.comando,
                'salida'        : list(self.salida),
                'bps_actual'    : self.bps_actual,
                'gbps_actual'   : round(self.bps_actual / 1e9, 4),
                'mbps_actual'   : round(self.bps_actual / 1e6, 2),
                'transferido'   : self.transferido,
                'transferido_mb': round(self.transferido / 1e6, 2),
                'transferido_gb': round(self.transferido / 1e9, 3),
                'retrans'       : self.retrans,
                'intervalo'     : self.intervalo_act,
                'es_resumen'    : self.es_resumen,
                'perdidos'      : self.perdidos,
                'total_dg'      : self.total_dg,
                'pct_perdidos'  : round(self.perdidos / self.total_dg * 100, 2) if self.total_dg else 0,
                'jitter'        : round(self.jitter, 3),
                'historial_bps' : list(self.historial_bps),
                'intervalos'    : list(self.intervalos),
            }


# Instancia global usada por el servidor Flask.
gestor_iperf = GestorIperf()
