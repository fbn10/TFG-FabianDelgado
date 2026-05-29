# Servidor web Flask de ESCILA.
#
# Expone las tres vistas HTML (Dashboard, Stream Editor e iperf3) y todas las
# llamadas que utiliza el frontend para controlar TRex e iperf3 desde el
# navegador.

import json
import time
import logging
from flask import Flask, render_template, request, jsonify, Response
from trex_manager import gestor
from iperf_manager import gestor_iperf

app = Flask(__name__)

# Reducimos el nivel de logging de Werkzeug para no llenar la terminal con
# las peticiones GET del polling de estado, dejando visibles solo los errores.
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)


# Paginas HTML servidas por Flask.

@app.route('/')
def pagina_principal():
    return render_template('dashboard.html')

@app.route('/streams')
def pagina_streams():
    return render_template('stream_editor.html')

@app.route('/iperf')
def pagina_iperf():
    return render_template('iperf.html')


# API de conexion con TRex.

@app.route('/api/conectar', methods=['POST'])
def conectar():
    return jsonify(gestor.conectar())

@app.route('/api/desconectar', methods=['POST'])
def desconectar():
    return jsonify(gestor.desconectar())

@app.route('/api/estado', methods=['GET'])
def estado():
    """Estado actual del gestor de TRex. El frontend lo consulta por polling
    cada dos segundos para reflejar las transiciones de estado en la barra
    superior."""
    return jsonify({
        'conectado'     : gestor.conectado,
        'estado'        : gestor.estado,
        'ultimo_error'  : gestor.ultimo_error,
        'trafico_activo': gestor.trafico_activo,
        'num_streams'   : len(gestor.streams_activos),
        'modo_dpdk'     : gestor.modo_dpdk,
    })


# API de control de trafico TRex.

@app.route('/api/trafico/iniciar', methods=['POST'])
def iniciar_trafico():
    """Recibe la lista de streams del editor y los arranca todos en TRex."""
    datos = request.get_json()
    if not datos or 'streams' not in datos:
        return jsonify({'exito': False, 'mensaje': 'No se recibio lista de streams'})
    lista = datos['streams']
    if not lista:
        return jsonify({'exito': False, 'mensaje': 'La lista de streams esta vacia'})
    return jsonify(gestor.iniciar_trafico(lista))

@app.route('/api/trafico/parar', methods=['POST'])
def parar_trafico():
    return jsonify(gestor.parar_trafico())

@app.route('/api/trafico/resetear', methods=['POST'])
def resetear():
    return jsonify(gestor.resetear_puertos())


# Estadisticas de TRex.

@app.route('/api/estadisticas', methods=['GET'])
def estadisticas():
    return jsonify(gestor.obtener_estadisticas())


# API de iperf3.

@app.route('/api/iperf/interfaces', methods=['GET'])
def iperf_interfaces():
    return jsonify(gestor_iperf.listar_interfaces())

@app.route('/api/iperf/iniciar', methods=['POST'])
def iperf_iniciar():
    cfg = request.get_json() or {}
    return jsonify(gestor_iperf.iniciar(cfg))

@app.route('/api/iperf/parar', methods=['POST'])
def iperf_parar():
    return jsonify(gestor_iperf.parar())

@app.route('/api/iperf/estado', methods=['GET'])
def iperf_estado():
    return jsonify(gestor_iperf.obtener_estado())


@app.route('/api/estadisticas/stream')
def estadisticas_stream():
    """Canal Server-Sent Events que envia las estadisticas de TRex una vez
    por segundo. Si el gestor falla en una iteracion devolvemos stats vacias
    para mantener la conexion abierta."""
    def generar():
        while True:
            try:
                datos = gestor.obtener_estadisticas()
            except Exception:
                datos = gestor._stats_vacias()
            yield f"data: {json.dumps(datos)}\n\n"
            time.sleep(1)
    return Response(generar(), mimetype='text/event-stream',
                    headers={'Cache-Control'    : 'no-cache',
                             'X-Accel-Buffering': 'no',
                             'Connection'       : 'keep-alive'})


# Arranque del servidor.

if __name__ == '__main__':
    print("=" * 50)
    print("  ESCILA - Generador de trafico de red")
    print("  http://localhost:5000")
    print("=" * 50)
    # debug=False es importante: en modo debug Flask se reinicia solo al
    # detectar cambios y eso mata la sesion abierta con TRex.
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
