# CBR Assiduidade — versão cloud

Arquitetura desta versão:

- Frontend: Firebase Hosting, que pode ser servido pelo domínio `assiduidade.cbrintranet.online`.
- Backend: Firebase Cloud Functions, endpoint `/api/*`.
- Base de dados: Firestore.
- Segurança dos dados: o browser não acede diretamente ao Firestore; só a Cloud Function acede.
- Passkeys: mantidas com `@simplewebauthn/server` no backend Node das Firebase Functions.

## 1. Criar projeto Firebase

1. Acede a https://console.firebase.google.com/
2. Cria um projeto, por exemplo `cbr-assiduidade`.
3. Vai a Build > Firestore Database.
4. Cria a base de dados em modo production.
5. Escolhe uma região europeia, idealmente `eur3` ou semelhante.

## 2. Instalar Firebase CLI

No PC:

```bash
npm install -g firebase-tools
firebase login
```

## 3. Ligar esta pasta ao Firebase

Dentro da pasta deste projeto:

```bash
firebase use --add
```

Escolhe o projeto Firebase que criaste.

## 4. Configurar variáveis do backend

Como a Firebase Functions v2 lê variáveis de ambiente no deploy, cria/edita `functions/.env`:

```env
PUBLIC_ORIGIN=https://assiduidade.cbrintranet.online
RP_ID=cbrintranet.online
RP_NAME=CBR Boutique Hotel - Assiduidade
EXTRA_ORIGINS=https://staff.cbrintranet.online,https://cbrintranet.online,http://localhost:5000,http://127.0.0.1:5000
ADMIN_EMAIL=manager
ADMIN_PASSWORD=troca_esta_password
```

Mantém `RP_ID=cbrintranet.online`, porque isso permite passkeys válidas para subdomínios como `assiduidade.cbrintranet.online` e `staff.cbrintranet.online`.

## 5. Instalar dependências

```bash
cd functions
npm install
cd ..
```

## 6. Testar localmente

```bash
firebase emulators:start --only hosting,functions,firestore
```

Abre:

```txt
http://localhost:5000
```

Nota: passkeys em localhost podem funcionar para testes, mas o teste real deve ser em HTTPS no domínio final.

## 7. Fazer deploy

```bash
firebase deploy
```

Isto publica:

- o frontend;
- a Cloud Function `api`;
- as regras Firestore fechadas.

## 8. Ligar o subdomínio assiduidade.cbrintranet.online

No Firebase Console:

1. Vai a Hosting.
2. Add custom domain.
3. Escreve `assiduidade.cbrintranet.online`.
4. O Firebase vai mostrar registos DNS.

No Cloudflare DNS:

1. Cria os registos que o Firebase pedir.
2. Se for CNAME, usa proxy DNS only durante a validação.
3. Depois de validado, podes deixar conforme recomendação do Firebase.

## 9. Primeiro acesso

Depois de propagado:

```txt
https://assiduidade.cbrintranet.online
```

Páginas principais:

```txt
/assiduidade-admin.html
/assiduidade-qr.html
/assiduidade-setup.html
/assiduidade.html
```

## 10. Ordem de teste

1. Entra em `/assiduidade-admin.html`.
2. Faz login com o manager.
3. Cria um colaborador.
4. Clica em Setup para copiar o link.
5. Abre o link no telemóvel do colaborador.
6. Cria a passkey.
7. Abre `/assiduidade-qr.html` no tablet.
8. Lê o QR com o telemóvel.
9. Faz Entrada ou Saída.
10. No manager, confirma em Tempo Real e na vista pessoa-a-pessoa.

## 11. Notas importantes

- Não há `data.json` em produção.
- Os dados ficam em Firestore.
- O GitHub passa a servir como controlo de versões.
- O deploy pode ser feito manualmente com `firebase deploy` ou automaticamente com GitHub Actions.
