const { createServer } = require('http');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const path = require('path');

function saveMemoryData() {
  try {
    const dataPath = path.join(__dirname, 'memory-data.json');
    fs.writeFileSync(dataPath, JSON.stringify(memoryData, null, 2));
    console.log('Memory data saved successfully');
  } catch (error) {
    console.error('Error saving memory data:', error);
  }
}

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

function handleProtectedResourceDiscovery(res) {
  const discovery = {
    resource: BASE_URL,
    authorization_servers: [BASE_URL],
    scopes_supported: ["mcp"],
    bearer_methods_supported: ["header"],
    resource_documentation: BASE_URL
  };
  
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(discovery, null, 2));
}

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
  // const client = clients.get(client_id);
  // if (!client) {
  //   res.writeHead(400, { 'Content-Type': 'text/html' });
  //   res.end('<h1>Error: Invalid client</h1>');
  //   return;
  // }
  
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

  function handleMCPMessage(req, res, sessionId) {
    console.log('=== HANDLING MCP MESSAGE ===');
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const message = JSON.parse(body);
        console.log('Received MCP message:', message);
        
        let response;
        
        if (message.method === 'initialize') {
          response = {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              protocolVersion: "2025-06-18",
              capabilities: {
                tools: { list: true, call: true },
                resources: {},
                prompts: {}
              },
              serverInfo: {
                name: "claude-memory-server", 
                version: "1.0.0"
              }
            }
          };
        } else if (message.method === 'notifications/initialized') {
          res.writeHead(200);
          res.end();
          return;
        } else if (message.method === 'resources/list') {
          response = {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              resources: []
            }
          };
        } else if (message.method === 'tools/list') {
          response = {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              tools: [
                {
                  name: "memory_read_graph",
                  description: "Read the entire knowledge graph from memory",
                  inputSchema: { type: "object", properties: {}, required: [] }
                },
                {
                  name: "memory_create_entities",
                  description: "Create multiple new entities in the knowledge graph",
                  inputSchema: {
                    type: "object",
                    properties: {
                      entities: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            name: { type: "string" },
                            entityType: { type: "string" },
                            observations: { type: "array", items: { type: "string" } }
                          },
                          required: ["name", "entityType", "observations"]
                        }
                      }
                    },
                    required: ["entities"]
                  }
                },
                {
                  name: "memory_add_observations",
                  description: "Add new observations to existing entities in the knowledge graph",
                  inputSchema: {
                    type: "object",
                    properties: {
                      observations: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            entityName: { type: "string" },
                            contents: { type: "array", items: { type: "string" } }
                          },
                          required: ["entityName", "contents"]
                        }
                      }
                    },
                    required: ["observations"]
                  }
                },
                {
                  name: "memory_search_nodes",
                  description: "Search for nodes in the knowledge graph based on a query",
                  inputSchema: {
                    type: "object",
                    properties: { query: { type: "string" } },
                    required: ["query"]
                  }
                },
                {
                  name: "memory_open_nodes", 
                  description: "Open specific nodes in the knowledge graph by their names",
                  inputSchema: {
                    type: "object",
                    properties: {
                      names: { type: "array", items: { type: "string" } }
                    },
                    required: ["names"]
                  }
                },
                {
                  name: "memory_create_relations",
                  description: "Create multiple new relations between entities",
                  inputSchema: {
                    type: "object",
                    properties: {
                      relations: {
                        type: "array",
                        items: {
                          type: "object", 
                          properties: {
                            from: { type: "string" },
                            to: { type: "string" },
                            relationType: { type: "string" }
                          },
                          required: ["from", "to", "relationType"]
                        }
                      }
                    },
                    required: ["relations"]
                  }
                },
                {
                  name: "memory_delete_entities",
                  description: "Delete multiple entities and their associated relations",
                  inputSchema: {
                    type: "object",
                    properties: {
                      entityNames: { type: "array", items: { type: "string" } }
                    },
                    required: ["entityNames"]
                  }
                },
                {
                  name: "memory_delete_observations",
                  description: "Delete specific observations from entities",
                  inputSchema: {
                    type: "object",
                    properties: {
                      deletions: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            entityName: { type: "string" },
                            observations: { type: "array", items: { type: "string" } }
                          },
                          required: ["entityName", "observations"]
                        }
                      }
                    },
                    required: ["deletions"]
                  }
                },
                {
                  name: "memory_delete_relations",
                  description: "Delete multiple relations from the knowledge graph",
                  inputSchema: {
                    type: "object",
                    properties: {
                      relations: {
                        type: "array",
                        items: {
                          type: "object",
                          properties: {
                            from: { type: "string" },
                            to: { type: "string" },
                            relationType: { type: "string" }
                          },
                          required: ["from", "to", "relationType"]
                        }
                      }
                    },
                    required: ["relations"]
                  }
                }
              ]
            }
          };
        } else if (message.method === 'tools/call') {
          const { name, arguments: args } = message.params;
          
          try {
            let toolResult;
            
            switch (name) {
              case 'memory_read_graph':
                toolResult = {
                  content: [{ type: "text", text: JSON.stringify(memoryData, null, 2) }]
                };
                break;
                
              case 'memory_create_entities':
                const { entities } = args;
                const createdEntities = [];
                
                entities.forEach(entity => {
                  const newEntity = {
                    type: "entity",
                    name: entity.name,
                    entityType: entity.entityType,
                    observations: entity.observations
                  };
                  memoryData.entities = memoryData.entities || [];
                  memoryData.entities.push(newEntity);
                  createdEntities.push({ entityName: entity.name, created: true });
                });
                
                saveMemoryData();
                toolResult = { content: [{ type: "text", text: JSON.stringify(createdEntities) }] };
                break;
                
              case 'memory_add_observations':
                const { observations } = args;
                const addResults = [];
                
                observations.forEach(obs => {
                  const entity = memoryData.entities.find(e => e.name === obs.entityName);
                  if (entity) {
                    entity.observations = entity.observations || [];
                    entity.observations.push(...obs.contents);
                    addResults.push({
                      entityName: obs.entityName,
                      addedObservations: obs.contents
                    });
                  }
                });
                
                saveMemoryData();
                toolResult = { content: [{ type: "text", text: JSON.stringify(addResults) }] };
                break;
                
              case 'memory_search_nodes':
                const { query } = args;
                const searchResults = [];
                
                memoryData.entities.forEach(entity => {
                  const matchesName = entity.name.toLowerCase().includes(query.toLowerCase());
                  const matchesType = entity.entityType.toLowerCase().includes(query.toLowerCase());
                  const matchesObservations = entity.observations && entity.observations.some(obs => 
                    obs.toLowerCase().includes(query.toLowerCase())
                  );
                  
                  if (matchesName || matchesType || matchesObservations) {
                    searchResults.push(entity);
                  }
                });
                
                toolResult = {
                  content: [{ 
                    type: "text", 
                    text: JSON.stringify({ entities: searchResults, relations: [] }) 
                  }]
                };
                break;
                
              case 'memory_open_nodes':
                const { names } = args;
                const openResults = [];
                
                names.forEach(name => {
                  const entity = memoryData.entities.find(e => e.name === name);
                  if (entity) openResults.push(entity);
                });
                
                const nodeRelations = memoryData.relations ? memoryData.relations.filter(rel => 
                  names.includes(rel.from) || names.includes(rel.to)
                ) : [];
                
                toolResult = {
                  content: [{ 
                    type: "text", 
                    text: JSON.stringify({ entities: openResults, relations: nodeRelations }) 
                  }]
                };
                break;
                
              case 'memory_create_relations':
                const { relations } = args;
                const createdRels = [];
                
                relations.forEach(rel => {
                  const newRelation = {
                    type: "relation",
                    from: rel.from,
                    to: rel.to, 
                    relationType: rel.relationType
                  };
                  memoryData.relations = memoryData.relations || [];
                  memoryData.relations.push(newRelation);
                  createdRels.push(newRelation);
                });
                
                saveMemoryData();
                toolResult = { content: [{ type: "text", text: JSON.stringify(createdRels) }] };
                break;
                
              case 'memory_delete_entities':
                const { entityNames } = args;
                
                memoryData.entities = memoryData.entities.filter(e => !entityNames.includes(e.name));
                memoryData.relations = memoryData.relations ? memoryData.relations.filter(r => 
                  !entityNames.includes(r.from) && !entityNames.includes(r.to)
                ) : [];
                
                saveMemoryData();
                toolResult = { 
                  content: [{ type: "text", text: JSON.stringify({ deletedEntities: entityNames, success: true }) }] 
                };
                break;
                
              case 'memory_delete_observations':
                const { deletions } = args;
                const deleteResults = [];
                
                deletions.forEach(del => {
                  const entity = memoryData.entities.find(e => e.name === del.entityName);
                  if (entity) {
                    entity.observations = entity.observations.filter(obs => !del.observations.includes(obs));
                    deleteResults.push({
                      entityName: del.entityName,
                      deletedObservations: del.observations
                    });
                  }
                });
                
                saveMemoryData();
                toolResult = { content: [{ type: "text", text: JSON.stringify(deleteResults) }] };
                break;
                
              case 'memory_delete_relations':
                const { relations: relsToDelete } = args;
                
                memoryData.relations = memoryData.relations ? memoryData.relations.filter(rel => {
                  return !relsToDelete.some(delRel => 
                    rel.from === delRel.from && rel.to === delRel.to && rel.relationType === delRel.relationType
                  );
                }) : [];
                
                saveMemoryData();
                toolResult = { 
                  content: [{ type: "text", text: JSON.stringify({ deletedRelations: relsToDelete, success: true }) }] 
                };
                break;
                
              default:
                toolResult = { content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }] };
            }
            
            response = { jsonrpc: "2.0", id: message.id, result: toolResult };
            
          } catch (toolError) {
            response = {
              jsonrpc: "2.0",
              id: message.id,
              error: { code: -32603, message: `Tool execution error: ${toolError.message}` }
            }
            };
          }
        
        // Get the SSE connection for this session
        const session = sessions.get(sessionId);
        if (session && session.res) {
          session.res.write(`data: ${JSON.stringify(response)}\n\n`);
          console.log('Sent response over SSE:', response);
        }
        
        res.writeHead(200);
        res.end();
        
      } catch (err) {
        console.error('Error parsing MCP message:', err);
        res.writeHead(400);
        res.end();
      }
    });
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
    case '/mcp':
  if (req.method === 'POST') {
    handleMCPMessage(req, res);
  } else {
    res.writeHead(405);
    res.end();
  }
  break;
  case '/':
    if (req.method === 'GET' && req.headers.accept === 'text/event-stream') {
      console.log('Claude requesting SSE connection...');
      
      const sessionId = crypto.randomUUID().replace(/-/g, '');
      
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache', 
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Authorization'
      });
      
      res.write('event: endpoint\n');
      res.write(`data: /messages?session_id=${sessionId}\n\n`);
      
      // STORE THE SESSION
      sessions.set(sessionId, { connected: true, res: res });
      
      const keepAlive = setInterval(() => {
        res.write('event: ping\n');
        res.write('data: {}\n\n');
      }, 30000);
      
      req.on('close', () => {
        clearInterval(keepAlive);
        console.log('SSE connection closed');
      });
      
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<h1>Server Running</h1>');
    }
    break;
    case '/messages':
      const query = parsedUrl.query;
      const sessionId = query.session_id;
      
      if (req.method === 'POST') {
        handleMCPMessage(req, res, sessionId);
      } else {
        res.writeHead(405);
        res.end();
      }
      break;
  case '/.well-known/oauth-protected-resource':
  handleProtectedResourceDiscovery(res);
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