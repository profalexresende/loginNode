const express = require('express'); // Importa o framework Express para criar o servidor e gerenciar rotas
const MongoClient = require('mongodb').MongoClient; // Importa a biblioteca do MongoDB para manipulação do banco de dados
const session = require('express-session'); // Biblioteca para gerenciamento de sessões
const bcrypt = require('bcrypt'); // Biblioteca para criptografar senhas

const app = express(); // Cria uma instância do aplicativo Express
const porta = 3000; // Define a porta do servidor

// Configuração do Express para processar formulários e gerenciar sessões
app.use(express.urlencoded({ extended: true })); // Habilita o suporte a formulários codificados em URL
app.use(express.json()); // Habilita o suporte a dados JSON
app.use(session({
    secret: 'segredo-super-seguro', // Chave usada para criptografar a sessão (deve ser mantida segura)
    resave: false, // Não salva a sessão se não houver alterações
    saveUninitialized: true, // Salva sessões não inicializadas (novas)
}));

// Configura a conexão com o banco de dados MongoDB
const urlMongo = 'mongodb://127.0.0.1:27017'; // URL de conexão com o MongoDB local
const nomeBanco = 'sistemaLogin'; // Nome do banco de dados

// Rota para exibir a página de registro (pública)
app.get('/registro', (req, res) => {
    res.sendFile(__dirname + '/views/registro.html'); // Retorna o formulário de registro ao usuário
});

// Rota para registrar um novo usuário (pública)
app.post('/registro', async (req, res) => {
    const cliente = new MongoClient(urlMongo, { useUnifiedTopology: true }); // Cria um novo cliente MongoDB
    try {
        await cliente.connect(); // Conecta ao banco de dados
        const banco = cliente.db(nomeBanco); // Seleciona o banco de dados
        const colecaoUsuarios = banco.collection('usuarios'); // Seleciona a coleção de usuários

        // Verifica se o nome de usuário já existe
        const usuarioExistente = await colecaoUsuarios.findOne({ usuario: req.body.usuario });

        if (usuarioExistente) {
            res.send('Usuário já existe! Tente outro nome de usuário.'); // Se o usuário já existir, retorna mensagem
        } else {
            // Criptografa a senha antes de salvar no banco de dados
            const senhaCriptografada = await bcrypt.hash(req.body.senha, 10);
            // Insere o novo usuário na coleção de usuários
            await colecaoUsuarios.insertOne({
                usuario: req.body.usuario, // Nome de usuário fornecido pelo formulário
                senha: senhaCriptografada // Senha criptografada
            });
            res.redirect('/login'); // Redireciona para a página de login após o registro bem-sucedido
        }
    } catch (erro) {
        res.send('Erro ao registrar o usuário.'); // Caso ocorra um erro na operação
    } finally {
        cliente.close(); // Fecha a conexão com o banco de dados
    }
});

// Rota para exibir a página de login (pública)
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html'); // Retorna o formulário de login ao usuário
});

// Rota para autenticar o usuário (pública)
app.post('/login', async (req, res) => {
    const cliente = new MongoClient(urlMongo, { useUnifiedTopology: true }); // Cria um novo cliente MongoDB
    try {
        await cliente.connect(); // Conecta ao banco de dados
        const banco = cliente.db(nomeBanco); // Seleciona o banco de dados
        const colecaoUsuarios = banco.collection('usuarios'); // Seleciona a coleção de usuários

        // Busca o usuário no banco de dados pelo nome fornecido
        const usuario = await colecaoUsuarios.findOne({ usuario: req.body.usuario });

        // Se o usuário existir e a senha estiver correta, cria a sessão
        if (usuario && await bcrypt.compare(req.body.senha, usuario.senha)) {
            req.session.usuario = req.body.usuario; // Salva o nome de usuário na sessão
            res.redirect('/bemvindo'); // Redireciona para a página protegida
        } else {
            res.redirect('/erro'); // Caso as credenciais sejam inválidas, redireciona para a página de erro
        }
    } catch (erro) {
        res.send('Erro ao realizar login.'); // Caso ocorra um erro na operação
    } finally {
        cliente.close(); // Fecha a conexão com o banco de dados
    }
});

// Middleware para proteger rotas, verificando se o usuário está autenticado
function protegerRota(req, res, proximo) {
    if (req.session.usuario) {
        proximo(); // Se o usuário estiver autenticado, prossegue para a próxima função
    } else {
        res.redirect('/login'); // Caso contrário, redireciona para a página de login
    }
}

// Rota protegida (acessível apenas após login)
app.get('/bemvindo', protegerRota, (req, res) => {
    res.sendFile(__dirname + '/views/bemvindo.html'); // Retorna a página de boas-vindas ao usuário autenticado
});

// Rota para exibir a página de erro
app.get('/erro', (req, res) => {
    res.sendFile(__dirname + '/views/erro.html'); // Retorna a página de erro ao usuário
});

// Rota para sair (logout) e destruir a sessão
app.get('/sair', (req, res) => {
    req.session.destroy((err) => { // Destroi a sessão ativa
        if (err) {
            return res.send('Erro ao sair!'); // Caso ocorra um erro ao destruir a sessão
        }
        res.redirect('/login'); // Redireciona para a página de login após logout
    });
});

// Inicia o servidor na porta especificada
app.listen(porta, () => {
    console.log(`Servidor rodando na porta ${porta}`); // Mensagem de confirmação no console
});
