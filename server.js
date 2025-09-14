const { createServer } = require('http');
const crypto = require('crypto');
const url = require('url');


// Your real memory data
const { memoryData, getAllEntities, getEntity } = require('./memory-data.js');

// OAuth and server configuration - using environment variables
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || 'https://claude-memory-server.onrender.com';
const PORT = process.env.PORT || 10000;

// Validate required environment variables
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.error('Missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET');
  process.exit(1);
}

// In-memory storage for demo (use database in production)
const clients = new Map();
const authCodes = new Map(); 
const accessTokens = new Map();
const sessions = new Map();

// OAuth Discovery endpoint
function handleDiscovery(res) {
  const discovery = {
    issuer: BASE_URL,
    authorization_endpoint: `${BASE_URL}/authorize`,
    token_endpoint: `${BASE_URL}/token`,
    registration_endpoint: `${BASE_URL}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["mcp"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"]
  };
  
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(discovery, null, 2));
}

// Dynamic Client Registration endpoint
function handleRegister(req, res) {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'method_not_allowed' }));
    return;
  }
  
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try {
      const registration = JSON.parse(body);
      
      // Generate client credentials
      const clientId = crypto.randomUUID();
      const clientSecret = crypto.randomBytes(32).toString('hex');
      
      // Store client info
      clients.set(clientId, {
        client_id: clientId,
        client_secret: clientSecret,
        client_name: registration.client_name || 'Unknown Client',
        redirect_uris: registration.redirect_uris || [],
        created_at: Date.now()
      });
      
      const response = {
        client_id: clientId,
        client_secret: clientSecret,
        client_name: registration.client_name || 'MCP Client',
        redirect_uris: registration.redirect_uris || [],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post"
      };
      
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_request' }));
    }
  });
}

// Authorization endpoint
function handleAuthorize(req, res) {
  const query = url.parse(req.url, true).query;
  const { 
    client_id, 
    redirect_uri, 
    response_type, 
    state, 
    code_challenge, 
    code_challenge_method 
  } = query;
  
  // Validate client
  const client = clients.get(client_id);
  if (!client) {
    res.writeHead(400, { 'Content-Type': 'text/html' });
    res.end('<h1>Error: Invalid client</h1>');
    return;
  }
  
  // For demo, auto-approve (in production, show consent screen)
  const authCode = crypto.randomBytes(32).toString('hex');
  
  // Store authorization code with PKCE info
  authCodes.set(authCode, {
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    expires_at: Date.now() + 600000 // 10 minutes
  });
  
  // Redirect back to client
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', authCode);
  if (state) redirectUrl.searchParams.set('state', state);
  
  res.writeHead(302, { 'Location': redirectUrl.toString() });
  res.end();
}

// Token endpoint
function handleToken(req, res) {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'method_not_allowed' }));
    return;
  }
  
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    try {
      const params = new URLSearchParams(body);
      const grantType = params.get('grant_type');
      
      if (grantType === 'authorization_code') {
        const code = params.get('code');
        const clientId = params.get('client_id');
        const codeVerifier = params.get('code_verifier');
        
        // Validate auth code
        const authInfo = authCodes.get(code);
        if (!authInfo || authInfo.expires_at < Date.now()) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        
        // Verify PKCE
        if (authInfo.code_challenge) {
          const hash = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
          if (hash !== authInfo.code_challenge) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'invalid_grant' }));
            return;
          }
        }
        
        // Generate tokens
        const accessToken = crypto.randomBytes(32).toString('hex');
        const refreshToken = crypto.randomBytes(32).toString('hex');
        
        // Store access token
        accessTokens.set(accessToken, {
          client_id: clientId,
          scope: 'mcp',
          expires_at: Date.now() + 3600000 // 1 hour
        });
        
        // Clean up auth code
        authCodes.delete(code);
        
        const response = {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: refreshToken,
          scope: 'mcp'
        };
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(response));
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'unsupported_grant_type' }));
      }
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid_request' }));
    }
  });
}

// Middleware to validate access token
function validateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }
  
  const token = authHeader.substring(7);
  const tokenInfo = accessTokens.get(token);
  
  if (!tokenInfo || tokenInfo.expires_at < Date.now()) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_token' }));
    return;
  }
  
  req.tokenInfo = tokenInfo;
  next();
}

// MCP tools/list endpoint (protected)
function handleToolsList(req, res) {
  validateToken(req, res, () => {
    const tools = {
      tools: [
        {
          name: "memory_read_graph",
          description: "Read the complete knowledge graph from memory",
          inputSchema: {
            type: "object",
            properties: {},
            required: []
          }
        }
      ]
    };
    
    res.writeHead(200, { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    res.end(JSON.stringify(tools));
  });
}

// MCP tools/call endpoint (protected)  
function handleToolsCall(req, res) {
  validateToken(req, res, () => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const request = JSON.parse(body);
        const { method, params } = request;
        
        if (method === 'tools/call' && params && params.name === 'memory_read_graph') {
          const response = {
            content: [
              {
                type: "text",
                text: JSON.stringify(memoryData, null, 2)
              }
            ]
          };
          
          res.writeHead(200, { 
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          });
          res.end(JSON.stringify(response));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'unknown_tool' }));
        }
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_request' }));
      }
    });
  });
}

// Root endpoint
function handleRoot(req, res) {
    // Check if Claude is asking for SSE
    if (req.method === 'GET' && req.headers.accept === 'text/event-stream') {
      console.log('Claude requesting SSE connection...');
      
      // SSE headers
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Authorization'
      });
      
      // Send initial MCP ready message
      res.write('event: message\n');
      res.write('data: {"jsonrpc":"2.0","method":"server/ready","params":{}}\n\n');
      
      // Keep connection alive
      const keepAlive = setInterval(() => {
        res.write('event: ping\n');
        res.write('data: {}\n\n');
      }, 30000);
      
      req.on('close', () => {
        clearInterval(keepAlive);
        console.log('SSE connection closed');
      });
      
    } else {
      // Regular browser request - show HTML page
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <h1>Claude Memory Server with OAuth</h1>
        <p>Server is running with SSE support!</p>
        <ul>
          <li><a href="/.well-known/oauth-authorization-server">OAuth Discovery</a></li>
          <li>OAuth endpoints: /authorize, /token, /register</li>  
          <li>MCP endpoints: /tools/list, /tools/call (require auth)</li>
        </ul>
      `);
    }
  }

// Original MCP handler for backward compatibility (protected)
function handleMCPRequest(req, res) {
  validateToken(req, res, () => {
    let body = '';
    
    req.on('data', chunk => {
      body += chunk.toString();
    });
    
    req.on('end', async () => {
      try {
        const { method, params } = JSON.parse(body);
        
        switch (method) {
          case 'tools/list':
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              tools: [
                {
                  name: "memory_read_graph",
                  description: "Read the entire knowledge graph",
                  inputSchema: { type: "object", properties: {} }
                }
              ]
            }));
            break;
            
          case 'tools/call':
            const { name } = params;
            
            if (name === 'memory_read_graph') {
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                content: [{ 
                  type: "text",
                  text: JSON.stringify(memoryData, null, 2)
                }]
              }));
            } else {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: `Unknown tool: ${name}` }));
            }
            break;
            
          default:
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: `Unknown method: ${method}` }));
        }
      } catch (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message }));
      }
    });
  });
}

// Main request handler
const server = createServer((req, res) => {
    // Add complete request logging
    console.log('=== INCOMING REQUEST ===');
    console.log('Time:', new Date().toISOString());
    console.log('Method:', req.method);
    console.log('URL:', req.url);
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('========================');
    
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
  
  // Enable CORS for all requests
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.writeHead(200).end();
  }
  
  // Route requests
  switch (path) {
    case '/':
      handleRoot(req, res);
      break;
    case '/.well-known/oauth-authorization-server':
      handleDiscovery(res);
      break;
    case '/register':
      handleRegister(req, res);
      break;
    case '/authorize':
      handleAuthorize(req, res);
      break;
    case '/token':
      handleToken(req, res);
      break;
    case '/tools/list':
      handleToolsList(req, res);
      break;
    case '/tools/call':
      handleToolsCall(req, res);
      break;
    default:
      // Handle the original MCP POST endpoint for backward compatibility
      if (req.method === 'POST' && path === '/') {
        handleMCPRequest(req, res);
      } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      }
  }
});

server.listen(PORT, () => {
  console.log(`OAuth MCP Server running on port ${PORT}`);
  console.log(`Discovery endpoint: ${BASE_URL}/.well-known/oauth-authorization-server`);
});