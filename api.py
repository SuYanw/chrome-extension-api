from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

servers = {
    'usuario': [
        {
            'name': 'glaubert',
            'host': '100.64.0.10',
        }
    ]
}


@app.route('/')
def login():
    return jsonify(servers)

@app.route('/login', methods=['POST'])
def index():
    dados = request.get_json()

    if(dados['user'] == 'glaubert'
        and dados['pass'] == '1234'):

        print("LOGADO")
        return jsonify({'status':200, 'reply':'999123791273912'})

    return jsonify({'status': 400, 'reply': 'senha errada'})


if __name__ == '__main__':
    app.run(debug=True)
