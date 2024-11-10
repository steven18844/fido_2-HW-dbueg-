const mysql = require('mysql2');
const crypto = require('crypto');//new
// 建立連接池
const pool = mysql.createPool({
  host: 'localhost',    // 或者你的 MySQL 容器 IP
  user: 'user',         // MySQL 資料庫的用戶名
  password: 'password', // MySQL 資料庫的密碼
  database: 'fidodb',   // 你之前創建的資料庫
  port: 3306            // MySQL 容器的埠
});

// 測試連接
pool.getConnection((err, connection) => {
  if (err) {
      console.error("資料庫連接失敗：", err);
      return;
  }
  console.log("資料庫連接成功！");
  connection.release();
});

const path = require('path');
// 引入 library
const express = require('express');
// express 引入的是一個 function
const app = express();
app.use(express.json()); //使用內建的 JSON 解析功能 處理 JSON 數據
// 建立一個不易產生衝突的 port 用來測試
const port = 5001;

// 如何處理不同的 request，參數分別為 url 和要執行的 function
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
})


// /register/begin 路由來返回 WebAuthn 註冊選項
app.post('/register/begin', (req, res) => {
  const { username } = req.body;  // 從前端接收 username
  // 生成隨機的挑戰碼
  const challenge = new Uint8Array(32);
  require('crypto').randomFillSync(challenge);
  // 將 username 轉換為 Base64 作為 user id
  const userId = Buffer.from(username).toString('base64');
  // 模擬生成的用戶ID和RP等選項
  const publicKeyCredentialCreationOptions = {
      challenge: Buffer.from(challenge).toString('base64'),
      rp: {
          name: "Tech Bridge",
      },
      user: {
        id: userId,  // 用戶輸入的 username 生成的 id
        name: username,  // 使用傳入的 username
        displayName: username,  // 這裡也可以是更易讀的名稱
      },
      pubKeyCredParams: [
          { alg: -7, type: "public-key" },
          { alg: -257, type: "public-key" },
      ],
      authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
      },
      timeout: 60000,
      attestation: "direct"
  };
  // 返回包含挑戰碼的公鑰創建選項
  res.json(publicKeyCredentialCreationOptions);
});

// /register/complete 路由來處理註冊完成後的憑證存儲
app.post('/register/complete', (req, res) => {
  const { credential, username } = req.body;  // 從請求中接收動態的 username 和 credential
  
  // 確保使用者存在
  pool.query(`INSERT IGNORE INTO users (username) VALUES (?)`, [username], (err, results) => {
    if (err) {
        console.error("無法插入使用者：", err);
        res.status(500).send("使用者儲存失敗");
        return;
    }

  const sql = `INSERT INTO credentials (username, id, publicKey, algo)
               VALUES (?, ?, ?, ?)`;

  pool.query(sql, [
      username,     // 使用者名稱
      credential.id,                   // 憑證ID
      Buffer.from(credential.rawId).toString('hex'),// 將 Buffer 轉換為 hex      // 公鑰
      credential.response.attestationObject ? credential.response.attestationObject.alg : null // 使用 attestationObject 的算法，確保不存在時為 null  // 公鑰演算法
  ], (err, results) => {
    if (err) {
      console.error("儲存資料到資料庫失敗：", err);
      res.status(500).send("儲存失敗");
    } 
    else {
      console.log("憑證成功儲存到資料庫", results);
      res.status(200).send("註冊成功");
      }
    });
  });
});

// /login/begin 路由來返回 WebAuthn 驗證選項
app.post('/login/begin', (req, res) => {
  const { username } = req.body;

  console.log("查詢的 username: ", username);// 檢查 username 的傳入
  // 從資料庫中取得對應使用者的 credentialId
  pool.query(`SELECT id FROM credentials WHERE username = ?`, [username], (err, results) => {
    if (err || results.length === 0) {
      console.error("無法找到對應的使用者或憑證：", err);
      return res.status(400).json({ error: "無法找到對應的使用者或憑證" });  // 確保這裡回傳 JSON 格式
    }
    const credentialId = results[0].id;
    // 生成並暫存挑戰碼
    const challengeFromLoginBegin = new Uint8Array(32);
    require('crypto').randomFillSync(challengeFromLoginBegin);
    const publicKeyCredentialRequestOptions = {
      challenge: Buffer.from(challengeFromLoginBegin).toString('base64'),  // 使用生成的挑戰碼
      allowCredentials: [{
        id: credentialId,
        type: "public-key",
        transports: ["usb", "nfc", "ble"]
      }],
      timeout: 60000,
      userVerification: "preferred"
    };

    // 返回驗證選項
    res.json(publicKeyCredentialRequestOptions);// 回傳 JSON 格式的驗證選項
  });
});

// /login/complete 路由來處理登入驗證
const { verifyAuthenticationResponse } = require('@simplewebauthn/server');//使用WebAuthn驗證函式庫來驗證客戶端發送的assertion。以下是使用 @simplewebauthn/server
app.post('/login/complete', (req, res) => {
  const assertion = req.body;

  // 從資料庫中取得對應的憑證資料
  pool.query(`SELECT publicKey FROM credentials WHERE id = ?`, [assertion.id], async (err, results) => {
    if (err || results.length === 0) {
      console.error("無法找到對應的憑證：", err);
      return res.status(400).send("憑證驗證失敗"); // 確保提前終止並返回錯誤
    }
 
    const storedPublicKey = results[0].publicKey;
    const currentChallenge= assertion.currentChallenge;
    try {
      // 使用 simplewebauthn 進行驗證
      const verification = await verifyAuthenticationResponse({
          credential: {
            id: assertion.id,
            rawId: Buffer.from(assertion.rawId),
            storedPublicKey: Buffer.from(storedPublicKey),
          },
          expectedChallenge: Buffer.from(assertion.currentChallenge),  // 使用之前儲存的挑戰碼進行驗證
          expectedOrigin: 'http://localhost:5001',  // 預期的 origin
          expectedRPID: 'localhost',  // 預期的 RP ID
          authenticator: {
              publicKey: storedPublicKey,
              counter: 0,  // 你可以從資料庫中取得相應的 counter
              credentialID: Buffer.from(assertion.rawId),
          },
      });

      if (verification.verified) {
      // 驗證成功，返回 200
      res.status(200).send("登入成功");
      } else {
      // 驗證失敗
        res.status(400).send("驗證失敗");
      }
    } catch (error) {
        console.error("登入過程中發生錯誤：", error);
        res.status(500).send("伺服器錯誤");
      }
    console.log("Received assertion : ", assertion); // 確認收到的 assertion id
  });
});

// 運行這個 port，參數分別為 port 和要執行的 function
app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});