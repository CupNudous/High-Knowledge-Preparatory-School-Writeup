# High Knowledge Preparatory School

###### Solved by @CupNudous

Este é um ctf de web sobre path traversal e bypass de um proxy Nginx.

## About the Challenge

O site da questão se trata de um blog simples que parece te ensinar coisas importantes sobre o mundo da computação, o desafio envolve a exploração dessa aplicação web com a configuração de um proxy reverso utilizando Nginx. O proxy é utilizado para passar as requisições para o backend. Além disso, o objetivo é identificar uma vulnerabilidade na configuração do servidor para explorar o sistema e capturar a flag.

[![r53l5t-2.png](https://i.postimg.cc/rw3C1QDQ/r53l5t-2.png)](https://postimg.cc/K17MF7rM)

Como dito, o proxy redireciona as requisições para o backend, o que elimina a possibilidade de usar ataques simples de `path traversal`. Resta então explorar o código backend do servidor, analisar e ver as possíveis vulnerabilidades

````

void handle_client(int socket_id) {
    char buffer[BUFFER_SIZE];
    char requested_filename[BUFFER_SIZE];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        memset(requested_filename, 0, sizeof(requested_filename));

        if (read(socket_id, buffer, BUFFER_SIZE) == 0) return;

        if (sscanf(buffer, "GET /%s", requested_filename) != 1)
            return build_response(socket_id, 500, "Internal Server Error", read_file("500.html"));

        FileWithSize *file = read_file(requested_filename);
        if (!file)
            return build_response(socket_id, 404, "Not Found", read_file("404.html"));

        build_response(socket_id, 200, "OK", file);
    }
}
````
## Solution
A principal vulnerabilidade pode ser identificada na função de manipulação de requisições do backend. Devido ao `while true` mal estruturado, o código permite enviar duas requisições HTTP em um único pedido, o que pode ser usado para explorar a aplicação por meio de um ataque similar ao de ``HTTP request smuggling``. A técnica consiste em forjar uma primeira requisição válida, seguida de uma segunda parte que é interpretada de forma separada pelo servidor backend, mas que é tratada como uma única requisição pelo proxy Nginx, permitindo a realização do `path traversal`. Resta agora, quebrar o buffer definido no começo do código do servidor backend, e enganar uma função que só permite a leiturar de arquivos como `.html` e `.js`, para então lançar uma requisição maliciosa através do `burpsuite`, por exemplo.

[![Screenshot-2025-04-04-142316.png](https://i.postimg.cc/T20V7Ryy/Screenshot-2025-04-04-142316.png)](https://postimg.cc/CdZndpsY)

Inserindo uma sequência de `A` gigantesca e `../` para retornar um diretório atrás, o buffer seria ultrapassado e isso daria acesso direto ao arquivo da flag, no entanto, não consegui montar um payload funcional que me desse o acesso, apesar de acreditar que a lógica esteja correta, visto que após alguns testes, a requisição maliciosa foi processada como esperado, mas não rodou por completo.

Ao pesquisar sobre esse tipo de vulnerabilidade e esclarecer dúvidas em relação a formação do payload, foi decidido enviar as requisições através do comando `curl`, simulando a requisição `HTTP` em duas partes, o comando final ficou então assim:

````
curl -v --http1.1 http://localhost:8081 \
  -H "Host: localhost" \
  -H "Content-Length: 1024" \
  -H "Foo: $(python3 -c 'print("a"*931)')" \
  --data-binary $'GET /'$(python3 -c 'print("/"*(1016-len("../../flag.txt")) + "../../flag.txt.js")')$'GET /index.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n'
````
A primeira parte é um ``GET`` para ``/index.html``, aparentemente legítima para o Nginx.
 Em seguida, temos o corpo contendo uma segunda requisição HTTP embutida, onde acessamos `../../flag.txt` camuflado com padding e .js, de modo a enganar o `read_file()` no backend.

O campo ``Content-Length: 1024`` e o cabeçalho ``Foo`` com ``931 bytes`` de a ajudam a alinhar os offsets e empurrar a segunda requisição para fora do buffer, sendo lida isoladamente pelo servidor backend.

Enviando a requisição através do `curl` algumas vezes, o terminal retorna apenas o código do `index.html`para as 2 requisições, no entanto, uma das tentativas retorna um 200 OK e o conteúdo da flag completo, como visto na imagem:

[![Screenshot-2025-04-10-091507.png](https://i.postimg.cc/5yqBpp0P/Screenshot-2025-04-10-091507.png)](https://postimg.cc/GTtTmFvY)
