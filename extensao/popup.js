document.getElementById('botao-requisicao').addEventListener('click', () => {
  //fazerRequisicaoGET();
  UserLogin();
});

const url = 'http://127.0.0.1:5000/'; // URL da API de exemplo

function fazerRequisicaoGET() {
  fetch(url)
    .then(response => {
      if (!response.ok) {
        throw new Error('Erro na requisição: ' + response.status);
      }
      return response.json(); // Converter a resposta para JSON
    })
    .then(data => {
      // Exibir os dados recebidos no elemento 'resultado'
      document.getElementById('resultado').textContent = JSON.stringify(data, null, 2);
    })
    .catch(error => {
      // Exibir erros no elemento 'resultado'
      document.getElementById('resultado').textContent = 'Erro: ' + error.message;
    });
}

function UserLogin() {


  const dados = {
    user: 'glaubert',
    pass: '1234'
  };


  console.log(JSON.stringify(dados))
  fetch(url + '/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(dados), // Converte os dados para JSON
    
  })
    .then(response => {
      if (!response.ok) {
        throw new Error('Erro na requisição: ' + response.status);
      }
      return response.json(); // Converter a resposta para JSON
    })
    .then(data => {
      // Exibir os dados recebidos no elemento 'resultado'
      var dados =  JSON.stringify(data, null, 2)
      document.getElementById('resultado').textContent = dados;
      
      var Key = JSON.parse(JSON.stringify(data, null, 2)).reply
      localStorage.setItem('vpnkey', Key)
    })
    .catch(error => {
      // Exibir erros no elemento 'resultado'
      document.getElementById('resultado').textContent = 'Erro: ' + error.message;
    });
}