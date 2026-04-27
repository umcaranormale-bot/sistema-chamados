using BCrypt.Net; // Para usar o BCrypt e hashear as senhas (instale o pacote BCrypt.Net-Next
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http; // Necessário para devolver respostas de erro e sucesso
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Mail;

var builder = WebApplication.CreateBuilder(args);

// Libera o CORS com segurança máxima para aceitar envios (POST)
builder.Services.AddCors(opcoes => opcoes.AddPolicy("PermitirTudo", p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

string pastaAnexos = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "anexos");
if (!Directory.Exists(pastaAnexos))
{
    Directory.CreateDirectory(pastaAnexos);
}

app.UseCors("PermitirTudo");
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        ctx.Context.Response.Headers.Append("Cache-Control", "public,max-age=86400");
    }
});


// ==========================================
// ROTA 1: SISTEMA DE LOGIN (POST)
// ==========================================
// Note que agora é MapPost! Ele recebe dados do site e guarda na variável 'dadosLogin'
app.MapPost("/api/login", (RequisicaoLogin dadosLogin) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";

    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        // Agora buscamos apenas pelo Email, pois vamos conferir a senha no C#
        string query = "SELECT Id, Nome, Perfil, Senha FROM Usuarios WHERE Email = @Email";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@Email", dadosLogin.Email);

            using (SqlDataReader leitor = comando.ExecuteReader())
            {
                if (leitor.Read())
                {
                    string senhaHashedBanco = leitor.GetString(3);

                    // A MÁGICA: O BCrypt compara a senha digitada com o Hash do banco
                    bool senhaCorreta = BCrypt.Net.BCrypt.Verify(dadosLogin.Senha, senhaHashedBanco);

                    if (senhaCorreta)
                    {
                        return Results.Ok(new
                        {
                            mensagem = "Login aprovado!",
                            id = leitor.GetInt32(0),
                            nome = leitor.GetString(1),
                            perfil = leitor.GetString(2),
                            email = dadosLogin.Email
                        });
                    }
                }
                return Results.Unauthorized();
            }
        }
    }
});

// ==========================================
// ROTA 1.1: SOLICITAR RECUPERAÇÃO DE SENHA (Gera o código)
// ==========================================
app.MapPost("/api/recuperar-senha/solicitar", (RequisicaoRecuperacao pedido) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";

    // 1. Gera um código aleatório de 6 números
    string codigoGerado = new Random().Next(100000, 999999).ToString();

    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();

        // 2. Tenta salvar o código no usuário que tem esse e-mail
        string query = "UPDATE Usuarios SET CodigoRecuperacao = @Codigo WHERE Email = @Email";
        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@Codigo", codigoGerado);
            comando.Parameters.AddWithValue("@Email", pedido.Email);

            int linhasAfetadas = comando.ExecuteNonQuery();

            // Se não afetou nenhuma linha, o e-mail não existe no banco!
            if (linhasAfetadas == 0) return Results.BadRequest(new { mensagem = "E-mail não encontrado no sistema." });
        }
    }

    // 3. Envia o e-mail com o código (Rodando em segundo plano)
    Task.Run(() => {
        try
        {
            var smtpClient = new SmtpClient("smtp.gmail.com")
            {
                Port = 587,
                Credentials = new NetworkCredential("tihbl1212@gmail.com", "ffwg sowd aniz tbpg"), // Coloque sua senha de app aqui!
                EnableSsl = true,
            };
            var mensagem = new MailMessage
            {
                From = new MailAddress("tihbl1212@gmail.com", "Suporte TI"),
                Subject = "Código de Recuperação de Senha",
                Body = $"<h2>Recuperação de Senha</h2><p>Seu código de segurança é: <b style='font-size: 24px; color: #0d6efd;'>{codigoGerado}</b></p><p>Não compartilhe este código com ninguém.</p>",
                IsBodyHtml = true
            };
            mensagem.To.Add(pedido.Email);
            smtpClient.Send(mensagem);
        }
        catch { }
    });

    return Results.Ok(new { mensagem = "Código enviado para o seu e-mail!" });
});

// ==========================================
// ROTA 1.2: REDEFINIR A SENHA (Valida o código e salva)
// ==========================================
app.MapPost("/api/recuperar-senha/redefinir", (RequisicaoNovaSenha pedido) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();

        // 1. Puxa o código que está salvo no banco
        string queryBusca = "SELECT CodigoRecuperacao FROM Usuarios WHERE Email = @Email";
        string codigoNoBanco = "";

        using (SqlCommand cmdBusca = new SqlCommand(queryBusca, conexao))
        {
            cmdBusca.Parameters.AddWithValue("@Email", pedido.Email);
            using (SqlDataReader leitor = cmdBusca.ExecuteReader())
            {
                if (leitor.Read()) codigoNoBanco = leitor.IsDBNull(0) ? "" : leitor.GetString(0);
            }
        }

        // 2. Confere se o código digitado bate com o do banco
        if (string.IsNullOrEmpty(codigoNoBanco) || codigoNoBanco != pedido.Codigo)
        {
            return Results.BadRequest(new { mensagem = "Código inválido ou expirado." });
        }

        // 3. Se o código estiver certo, faz o Hash da nova senha e salva
        string novaSenhaCriptografada = BCrypt.Net.BCrypt.HashPassword(pedido.NovaSenha);

        string queryUpdate = "UPDATE Usuarios SET Senha = @NovaSenha, CodigoRecuperacao = NULL WHERE Email = @Email";
        using (SqlCommand cmdUpdate = new SqlCommand(queryUpdate, conexao))
        {
            cmdUpdate.Parameters.AddWithValue("@NovaSenha", novaSenhaCriptografada);
            cmdUpdate.Parameters.AddWithValue("@Email", pedido.Email);
            cmdUpdate.ExecuteNonQuery();
        }

        return Results.Ok(new { mensagem = "Senha alterada com sucesso!" });
    }
});

// ==========================================
// ROTA 2: CRIAR NOVO CHAMADO (POST)
// ==========================================
app.MapPost("/api/chamados", async (HttpContext contexto) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    var form = await contexto.Request.ReadFormAsync();

    Random sorteio = new Random();
    string numeroGerado = "TIC-" + sorteio.Next(10000, 99999).ToString();

    string caminhoAnexo = null;
    if (form.Files.Count > 0)
    {
        var arquivo = form.Files[0];
        if (arquivo.Length > 0)
        {
            string pastaDestino = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "anexos");
            if (!Directory.Exists(pastaDestino)) Directory.CreateDirectory(pastaDestino);

            string nomeLimpo = arquivo.FileName.Replace("\"", "").Replace("'", "").Replace(" ", "_");
            string nomeArquivo = numeroGerado + "_" + nomeLimpo;
            string caminhoCompleto = Path.Combine(pastaDestino, nomeArquivo);

            using (var stream = new FileStream(caminhoCompleto, FileMode.Create))
            {
                await arquivo.CopyToAsync(stream);
            }
            caminhoAnexo = "/anexos/" + nomeArquivo;
        }
    }

    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        string query = @"INSERT INTO Chamados 
                         (Nome, NumeroChamado, Categoria, Setor, DescricaoProblema, IP_Computador, Ramal, UsuarioId, CaminhoAnexo) 
                         VALUES 
                         (@Nome, @Numero, @Categoria, @Setor, @Descricao, @IP, @Ramal, @UsuarioId, @Anexo)";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@Nome", form["Nome"].ToString());
            comando.Parameters.AddWithValue("@Numero", numeroGerado);
            comando.Parameters.AddWithValue("@Categoria", form["Categoria"].ToString());
            comando.Parameters.AddWithValue("@Setor", form["Setor"].ToString());
            comando.Parameters.AddWithValue("@Descricao", form["DescricaoProblema"].ToString());
            comando.Parameters.AddWithValue("@UsuarioId", int.Parse(form["UsuarioId"]));

            string ramal = form["Ramal"].ToString();
            comando.Parameters.AddWithValue("@Ramal", string.IsNullOrEmpty(ramal) ? DBNull.Value : ramal);

            // 👇 CORREÇÃO DO IP: Agora o C# pega o IP que veio da caixinha (mesmo se o usuário alterou)
            string ipDaCaixinha = form["IP"].ToString();
            comando.Parameters.AddWithValue("@IP", string.IsNullOrEmpty(ipDaCaixinha) ? DBNull.Value : ipDaCaixinha);

            comando.Parameters.AddWithValue("@Anexo", string.IsNullOrEmpty(caminhoAnexo) ? DBNull.Value : caminhoAnexo);
            comando.ExecuteNonQuery();

            // Task de email continua aqui silenciosa...
            _ = Task.Run(() => {
                string emailUsuario = form["Email"].ToString();
                string nomeUsuario = form["Nome"].ToString();

                _ = Task.Run(() => EnviarEmailConfirmacao(emailUsuario, nomeUsuario, int.Parse(numeroGerado.Replace("TIC-", ""))));
            });

            return Results.Ok(new { mensagem = "Chamado criado com sucesso!", numero = numeroGerado });
        }
    }
});

// ==========================================
// ROTA 2.1: PAINEL TÉCNICO (Puxar TODOS os chamados)
// ==========================================
app.MapGet("/api/chamados", () =>
{
    try
    {
        string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
        using (SqlConnection conexao = new SqlConnection(conexaoString))
        {
            conexao.Open();
            string query = @"SELECT Id, Nome, NumeroChamado, Categoria, Setor, DescricaoProblema, StatusChamado, Format(DataCriacao, 'dd/MM/yyyy HH:mm') as Data, SolucaoTecnica, IP_Computador, CaminhoAnexo, Ramal
                             FROM Chamados ORDER BY DataCriacao DESC";

            using (SqlCommand comando = new SqlCommand(query, conexao))
            using (SqlDataReader leitor = comando.ExecuteReader())
            {
                var listaChamados = new List<object>();
                while (leitor.Read())
                {
                    listaChamados.Add(new
                    {
                        id = leitor.GetInt32(0),
                        nome = leitor.IsDBNull(1) ? "Usuário" : leitor.GetString(1),
                        numero = leitor.IsDBNull(2) ? "Sem Protocolo" : leitor.GetString(2),
                        categoria = leitor.IsDBNull(3) ? "Sem Categoria" : leitor.GetString(3),
                        setor = leitor.IsDBNull(4) ? "Sem Setor" : leitor.GetString(4),
                        descricao = leitor.IsDBNull(5) ? "Sem descrição" : leitor.GetString(5),
                        status = leitor.IsDBNull(6) ? "Aberto" : leitor.GetString(6),
                        data = leitor.IsDBNull(7) ? "Data não registrada" : leitor.GetString(7),
                        solucaoTecnica = leitor.IsDBNull(8) ? null : leitor.GetString(8),
                        ip = leitor.IsDBNull(9) ? "Não detectado" : leitor.GetString(9),
                        anexo = leitor.IsDBNull(10) ? null : leitor.GetString(10),
                        ramal = leitor.IsDBNull(11) ? "N/A" : leitor.GetString(11)
                    });
                }
                return Results.Ok(listaChamados);
            }
        }
    }
    catch (Exception erro)
    {
        // 👇 SE DER ERRO, VAI APARECER EM VERMELHO NO SEU CONSOLE!
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\n❌ ERRO NA ROTA DE BUSCAR CHAMADOS (TÉCNICO):");
        Console.WriteLine(erro.Message);
        Console.ResetColor();
        return Results.Problem(erro.Message);
    }
});

// ==========================================
// ROTA 2.2: ATUALIZAR STATUS DO CHAMADO
// ==========================================
app.MapPost("/api/chamados/atualizar-status", (StatusRequest pedido) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        // Atualiza o status E a solução técnica
        string query = "UPDATE Chamados SET StatusChamado = @status, SolucaoTecnica = @solucao WHERE Id = @id";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@id", pedido.ChamadoId);
            comando.Parameters.AddWithValue("@status", pedido.NovoStatus);
            comando.Parameters.AddWithValue("@solucao", (object)pedido.Solucao ?? DBNull.Value);
            comando.ExecuteNonQuery();
        }

        // Se o chamado foi Concluído, envia o e-mail com a solução
        if (pedido.NovoStatus == "Concluído" && !string.IsNullOrEmpty(pedido.Solucao))
        {
            Task.Run(() => {
                try
                {
                    // Precisamos buscar o e-mail e o nome do usuário dono deste chamado
                    string emailDestino = "";
                    string nomeDestino = "";
                    string queryUser = "SELECT u.Email, u.Nome FROM Chamados c JOIN Usuarios u ON c.UsuarioId = u.Id WHERE c.Id = @Id";

                    using (SqlConnection conn = new SqlConnection(conexaoString))
                    {
                        conn.Open();
                        using (SqlCommand cmd = new SqlCommand(queryUser, conn))
                        {
                            cmd.Parameters.AddWithValue("@Id", pedido.ChamadoId);
                            using (SqlDataReader reader = cmd.ExecuteReader())
                            {
                                if (reader.Read())
                                {
                                    emailDestino = reader.GetString(0);
                                    nomeDestino = reader.GetString(1);
                                }
                            }
                        }
                    }

                    if (!string.IsNullOrEmpty(emailDestino))
                    {
                        var smtpClient = new SmtpClient("smtp.gmail.com")
                        {
                            Port = 587,
                            // 👇 SUA SENHA ENTRA AQUI NOVAMENTE
                            Credentials = new NetworkCredential("tihbl1212@gmail.com", "ffwg sowd aniz tbpg"),
                            EnableSsl = true,
                        };

                        var mensagem = new MailMessage
                        {
                            From = new MailAddress("tihbl1212@gmail.com", "Suporte TI Hospital"),
                            Subject = "Seu chamado foi concluído!",
                            Body = $@"
                                <div style='font-family: Arial, sans-serif; color: #333;'>
                                    <h2>Olá, {nomeDestino}!</h2>
                                    <p>O seu chamado foi atendido e finalizado pela equipe de TI.</p>
                                    <div style='background-color: #d1e7dd; padding: 15px; border-left: 5px solid #198754; margin: 20px 0;'>
                                        <p style='margin: 0; color: #0f5132;'><strong>✅ Solução Técnica:</strong><br><br>{pedido.Solucao}</p>
                                    </div>
                                    <p>Qualquer dúvida, estamos à disposição.</p>
                                </div>",
                            IsBodyHtml = true
                        };
                        mensagem.To.Add(emailDestino);
                        smtpClient.Send(mensagem);
                    }
                }
                catch (Exception ex) { Console.WriteLine("Erro ao enviar email de conclusão: " + ex.Message); }
            });
        }
        return Results.Ok();
    }
});

// ==========================================
// ROTA INTERMEDIÁRIA: APENAS CONFERE SE O CÓDIGO BATE
// ==========================================
app.MapPost("/api/recuperar-senha/validar-codigo", (RequisicaoValidarCodigo pedido) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        string queryBusca = "SELECT CodigoRecuperacao FROM Usuarios WHERE Email = @Email";
        string codigoNoBanco = "";

        using (SqlCommand cmdBusca = new SqlCommand(queryBusca, conexao))
        {
            cmdBusca.Parameters.AddWithValue("@Email", pedido.Email);
            using (SqlDataReader leitor = cmdBusca.ExecuteReader())
            {
                if (leitor.Read()) codigoNoBanco = leitor.IsDBNull(0) ? "" : leitor.GetString(0);
            }
        }

        if (string.IsNullOrEmpty(codigoNoBanco) || codigoNoBanco != pedido.Codigo)
        {
            return Results.BadRequest(new { mensagem = "Código incorreto. Tente novamente." });
        }

        return Results.Ok(new { mensagem = "Código aprovado!" });
    }
});

// Classe necessária para receber o pacote JSON do status


// ==========================================
// ROTA 3: CRIAR NOVA CONTA DE USUÁRIO (POST)
// ==========================================
app.MapPost("/api/usuarios", (RequisicaoCadastro novoUsuario) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";

    // CRIPTOGRAFIA: Transformando a senha em Hash antes de salvar
    string senhaCriptografada = BCrypt.Net.BCrypt.HashPassword(novoUsuario.Senha);

    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        string query = "INSERT INTO Usuarios (Nome, Email, Senha, Perfil) VALUES (@Nome, @Email, @Senha, 'Comum')";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@Nome", novoUsuario.Nome);
            comando.Parameters.AddWithValue("@Email", novoUsuario.Email);
            comando.Parameters.AddWithValue("@Senha", senhaCriptografada); // Salvando a versão segura

            try
            {
                comando.ExecuteNonQuery();
                return Results.Ok(new { mensagem = "Conta criada com segurança!" });
            }
            catch
            {
                return Results.BadRequest(new { mensagem = "Erro ao criar conta." });
            }
        }
    }
});

// ===============================================
// ROTA 4: USUÁRIO COMUM VER APENAS O CHAMADO DELE
// ===============================================
// ===============================================
// ROTA 4: PUXAR CHAMADOS ESPECÍFICOS DO USUÁRIO
// ===============================================
app.MapGet("/api/chamados/usuario/{id}", (int id) =>
{
    try
    {
        string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
        using (SqlConnection conexao = new SqlConnection(conexaoString))
        {
            conexao.Open();
            string query = @"SELECT NumeroChamado, Categoria, Format(DataCriacao, 'dd/MM/yyyy HH:mm') as Data, StatusChamado, DescricaoProblema, SolucaoTecnica, Id, CaminhoAnexo, Setor, IP_Computador, Ramal 
                             FROM Chamados WHERE UsuarioId = @Id ORDER BY DataCriacao DESC";

            using (SqlCommand comando = new SqlCommand(query, conexao))
            {
                comando.Parameters.AddWithValue("@Id", id);
                using (SqlDataReader leitor = comando.ExecuteReader())
                {
                    var listaChamados = new List<object>();
                    while (leitor.Read())
                    {
                        listaChamados.Add(new
                        {
                            numero = leitor.IsDBNull(0) ? "Sem Protocolo" : leitor.GetString(0),
                            categoria = leitor.IsDBNull(1) ? "Sem Categoria" : leitor.GetString(1),
                            data = leitor.IsDBNull(2) ? "Data não registrada" : leitor.GetString(2),
                            status = leitor.IsDBNull(3) ? "Aberto" : leitor.GetString(3),
                            descricao = leitor.IsDBNull(4) ? "Sem descrição" : leitor.GetString(4),
                            solucaoTecnica = leitor.IsDBNull(5) ? null : leitor.GetString(5),
                            id = leitor.GetInt32(6),
                            anexo = leitor.IsDBNull(7) ? null : leitor.GetString(7),
                            setor = leitor.IsDBNull(8) ? "N/A" : leitor.GetString(8),
                            ip = leitor.IsDBNull(9) ? "Não detectado" : leitor.GetString(9),
                            ramal = leitor.IsDBNull(10) ? "N/A" : leitor.GetString(10)
                        });
                    }
                    return Results.Ok(listaChamados);
                }
            }
        }
    }
    catch (Exception erro)
    {
        // 👇 SE DER ERRO, VAI APARECER EM VERMELHO NO SEU CONSOLE!
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\n❌ ERRO NA ROTA DO USUÁRIO:");
        Console.WriteLine(erro.Message);
        Console.ResetColor();
        return Results.Problem(erro.Message);
    }
});
// ==========================================
// ROTA 5: TECNICO VER TODOS OS CHAMADO
// ==========================================

app.MapGet("/api/chamados/todos", () =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    List<object> lista = new List<object>();

    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        // Buscamos tudo e fazemos um JOIN para saber o nome de quem abriu
        string query = @"SELECT c.Id, c.NumeroChamado, c.Categoria, c.Setor, c.StatusChamado, u.Nome 
                         FROM Chamados c 
                         JOIN Usuarios u ON c.UsuarioId = u.Id 
                         ORDER BY c.DataCriacao DESC";
        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            using (SqlDataReader leitor = comando.ExecuteReader())
            {
                while (leitor.Read())
                {
                    lista.Add(new
                    {
                        id = leitor.GetInt32(0),
                        numero = leitor.GetString(1),
                        categoria = leitor.GetString(2),
                        setor = leitor.GetString(3),
                        status = leitor.GetString(4),
                        usuario = leitor.GetString(5)
                    });
                }
            }
        }
    }
    return lista;
});

// ==========================================
// ROTA 6: SALVAR UM NOVO COMENTÁRIO/MENSAGEM
// ==========================================
app.MapPost("/api/chamados/comentario", (ComentarioRequest pedido) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();
        string query = @"INSERT INTO ComentariosChamado (ChamadoId, RemetenteId, Mensagem) 
                         VALUES (@ChamadoId, @RemetenteId, @Mensagem)";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@ChamadoId", pedido.ChamadoId);
            comando.Parameters.AddWithValue("@RemetenteId", pedido.RemetenteId);
            comando.Parameters.AddWithValue("@Mensagem", pedido.Mensagem);
            comando.ExecuteNonQuery();
        }
        return Results.Ok(new { mensagem = "Mensagem enviada com sucesso!" });
    }
});


// ==========================================
// ROTA 6.1: PUXAR CHAT E MARCAR COMO LIDO GLOBALMENTE
// ==========================================
app.MapGet("/api/chamados/{id}/comentarios/{perfil}", (int id, string perfil) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();

        // 1. MÁGICA GLOBAL: Marca como lidas apenas as mensagens enviadas pela "outra pessoa"
        string queryUpdate = @"
            UPDATE ComentariosChamado 
            SET Lido = 1 
            WHERE ChamadoId = @ChamadoId 
            AND Lido = 0
            AND RemetenteId IN (SELECT Id FROM Usuarios WHERE Perfil <> @Perfil)";

        using (SqlCommand cmdUpdate = new SqlCommand(queryUpdate, conexao))
        {
            cmdUpdate.Parameters.AddWithValue("@ChamadoId", id);
            cmdUpdate.Parameters.AddWithValue("@Perfil", perfil);
            cmdUpdate.ExecuteNonQuery();
        }

        // 2. Busca o histórico normalmente para desenhar o chat
        string query = @"SELECT c.Id, c.Mensagem, Format(c.DataEnvio, 'dd/MM/yyyy HH:mm') as DataEnvio, u.Nome, u.Perfil, c.RemetenteId
                         FROM ComentariosChamado c
                         INNER JOIN Usuarios u ON c.RemetenteId = u.Id
                         WHERE c.ChamadoId = @ChamadoId
                         ORDER BY c.DataEnvio ASC";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@ChamadoId", id);
            using (SqlDataReader leitor = comando.ExecuteReader())
            {
                var listaComentarios = new List<object>();
                while (leitor.Read())
                {
                    listaComentarios.Add(new
                    {
                        id = leitor.GetInt32(0),
                        mensagem = leitor.GetString(1),
                        data = leitor.GetString(2),
                        nomeRemetente = leitor.GetString(3),
                        perfilRemetente = leitor.GetString(4),
                        remetenteId = leitor.GetInt32(5)
                    });
                }
                return Results.Ok(listaComentarios);
            }
        }
    }
});

// ==========================================
// ROTA 7: RADAR GLOBAL (SÓ CONTA AS MENSAGENS DO OUTRO PERFIL)
// ==========================================
app.MapGet("/api/notificacoes/chat/{perfil}", (string perfil) =>
{
    string conexaoString = "Server=.; Database=SistemaTI; Integrated Security=True; TrustServerCertificate=True;";
    using (SqlConnection conexao = new SqlConnection(conexaoString))
    {
        conexao.Open();

        // Essa consulta só conta as mensagens com "Lido = 0" que não foram enviadas pelo seu perfil
        string query = @"
            SELECT c.ChamadoId, 
                   COUNT(*) AS TotalNaoLidas, 
                   MAX(c.Id) AS UltimaMensagemId
            FROM ComentariosChamado c
            INNER JOIN Usuarios u ON c.RemetenteId = u.Id
            WHERE c.Lido = 0 AND u.Perfil <> @Perfil
            GROUP BY c.ChamadoId";

        using (SqlCommand comando = new SqlCommand(query, conexao))
        {
            comando.Parameters.AddWithValue("@Perfil", perfil);
            using (SqlDataReader leitor = comando.ExecuteReader())
            {
                var lista = new List<object>();
                while (leitor.Read())
                {
                    lista.Add(new
                    {
                        chamadoId = leitor.GetInt32(0),
                        totalNaoLidas = leitor.GetInt32(1), // Retorna direto o número exato
                        ultimaMensagemId = leitor.GetInt32(2)
                    });
                }
                return Results.Ok(lista);
            }
        }
    }
});

// ==========================================
// INÍCIO: ROTA 8 (DESCOBRIR IP COM PROTEÇÃO DE ROTEADOR)
// ==========================================
app.MapGet("/api/meu-ip", (HttpContext contexto) =>
{
    // 1. Tenta ler a "etiqueta secreta" que o roteador deixa com o IP verdadeiro do computador
    string ipReal = contexto.Request.Headers["X-Forwarded-For"].FirstOrDefault();

    // 2. Se a etiqueta estiver vazia, pega o IP direto da porta
    if (string.IsNullOrEmpty(ipReal))
    {
        ipReal = contexto.Connection.RemoteIpAddress?.ToString();
    }
    else
    {
        // Às vezes o roteador manda uma lista de IPs separados por vírgula. Pegamos só o primeiro (que é o do usuário).
        ipReal = ipReal.Split(',')[0].Trim();
    }

    if (ipReal == "::1" || ipReal == "127.0.0.1") ipReal = "Localhost";

    return Results.Ok(new { meuIp = ipReal });
});

// Rota temporária para gerar hashes BCrypt
app.MapGet("/api/gerador/{senha}", (string senha) =>
{
    string hash = BCrypt.Net.BCrypt.HashPassword(senha);
    return Results.Ok(new
    {
        SenhaDigitada = senha,
        HashParaOBanco = hash
    });
});

void EnviarEmailConfirmacao(string emailDestino, string nomeUsuario, int numeroChamado)
{
    try
    {
        // 1. Configurar o carteiro (SMTP do Google)
        var smtpClient = new SmtpClient("smtp.gmail.com")
        {
            Port = 587,
            Credentials = new NetworkCredential("tihbl1212@gmail.com", "ffwg sowd aniz tbpg"),
            EnableSsl = true,
        };

        // 2. Escrever a carta
        var mensagem = new MailMessage
        {
            From = new MailAddress("tihbl1212@gmail.com", "Suporte TI Hospital"),
            Subject = $"Confirmado: Chamado #{numeroChamado} aberto com sucesso",
            Body = $@"
                <div style='font-family: Arial, sans-serif; color: #333;'>
                    <h2>Olá, {nomeUsuario}!</h2>
                    <p>Seu chamado número <b>{numeroChamado}</b> foi registrado com sucesso na fila da TI.</p>
                    <p>Nossa equipe já foi notificada e em breve um técnico fará o atendimento.</p>
                    <br>
                    <p>Atenciosamente,<br><b>Equipe de Suporte Técnico</b></p>
                </div>",
            IsBodyHtml = true // Permite usar tags HTML para deixar o e-mail bonito
        };

        // 3. Colocar o destinatário e enviar
        mensagem.To.Add(emailDestino);
        smtpClient.Send(mensagem);
    }
    catch (Exception ex)
    {
        // Se a internet cair ou o proxy bloquear a porta 587, o sistema avisa no painel, 
        // mas NÃO trava a tela do usuário.
        Console.WriteLine($"Erro ao enviar e-mail: {ex.Message}");
    }
}

// Aviso visual para você saber que a tela preta carregou!
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("\n=======================================================");
Console.WriteLine("✅ API DO HELP DESK INICIADA COM SUCESSO!");
Console.WriteLine("📡 O Radar Global de Notificações está online.");
Console.WriteLine("⏳ Aguardando acessos dos painéis...");
Console.WriteLine("=======================================================\n");
Console.ResetColor();

// Mantém o servidor ligado
app.Run();

// ==========================================
// CLASSES (MOLDES DE DADOS)
// ==========================================
// Isso avisa ao C# qual é o formato exato dos dados que o HTML vai enviar
class RequisicaoLogin
{
    public string Email { get; set; }
    public string Senha { get; set; }
}

// Molde dos dados que virão do site quando criarem um chamado
class RequisicaoChamado
{
    public string Categoria { get; set; }
    public string Nome { get; set; }
    public string Email { get; set; }
    public string Setor { get; set; }
    public string DescricaoProblema { get; set; }
    public string IP { get; set; }
    public string Ramal { get; set; }
    public int UsuarioId { get; set; }
}

class RequisicaoCadastro
{
    public string Nome { get; set; }
    public string Email { get; set; }
    public string Senha { get; set; }
}

public class StatusRequest
{
    public int ChamadoId { get; set; }
    public string NovoStatus { get; set; }
    public string Solucao { get; set; } // Campo novo
}

public class ComentarioRequest
{
    public int ChamadoId { get; set; }
    public int RemetenteId { get; set; }
    public string Mensagem { get; set; }
}
class AtualizarStatus { public int ChamadoId { get; set; } public string NovoStatus { get; set; } }
class RequisicaoRecuperacao { public string Email { get; set; } }
class RequisicaoNovaSenha { public string Email { get; set; } public string Codigo { get; set; } public string NovaSenha { get; set; } }
public class RequisicaoValidarCodigo { public string Email { get; set; } public string Codigo { get; set; } }