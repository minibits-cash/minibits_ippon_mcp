import 'dotenv/config'
import { randomUUID } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js'
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js'
import { z } from 'zod'
import prisma from './utils/prismaClient'
import { log } from './services/logService'

const IPPON_URL = process.env.IPPON_URL || 'http://localhost:3001'
const MCP_PORT = parseInt(process.env.MCP_PORT || '3002')
const TRANSPORT = process.env.MCP_TRANSPORT || 'stdio'


// --- Session-scoped state ---

interface SessionState {
    sessionId: string | null
    accessKey: string | null
}


async function initSession(state: SessionState): Promise<string> {
    const session = await prisma.mcpSession.create({ data: {} })
    state.sessionId = session.id
    log.info(`Session created: ${state.sessionId}`)
    return state.sessionId
}


async function getSessionAccessKey(state: SessionState): Promise<string> {
    if (state.accessKey) return state.accessKey
    if (!state.sessionId) throw new Error('No active session')

    const session = await prisma.mcpSession.findUnique({ where: { id: state.sessionId } })
    if (!session?.accessKey) throw new Error('No wallet bound to this session. Call create_wallet first.')

    state.accessKey = session.accessKey
    return state.accessKey
}


async function apiCall(
    state: SessionState,
    method: 'GET' | 'POST',
    path: string,
    body?: Record<string, unknown>,
    auth = true,
): Promise<{ ok: boolean, data: any, status: number }> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }

    if (auth) {
        const key = await getSessionAccessKey(state)
        headers['Authorization'] = `Bearer ${key}`
    }

    const res = await fetch(`${IPPON_URL}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
    })

    const data = await res.json()
    return { ok: res.ok, data, status: res.status }
}


function textResult(data: unknown, isError = false) {
    return {
        content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
        isError,
    }
}


async function handleApiResult(result: { ok: boolean, data: any, status: number }) {
    if (!result.ok) {
        return textResult(result.data?.error || result.data, true)
    }
    return textResult(result.data)
}


// --- Server factory (creates a new server with session-scoped state) ---

function createIpponMcpServer(): { server: McpServer, state: SessionState } {
    const state: SessionState = { sessionId: null, accessKey: null }

    const server = new McpServer({
        name: 'minibits-ippon',
        version: '1.0.0',
    })

    // --- Public tools ---

    server.registerTool(
        'get_info',
        {
            description: 'Get Ippon service info: status, mint URL, unit, and global limits',
        },
        async () => {
            const result = await apiCall(state, 'GET', '/v1/info', undefined, false)
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'create_wallet',
        {
            description: 'Create a new ecash wallet and bind it to this session. Optionally fund it with an initial ecash token. Returns wallet info (wallet access key is not exposed).',
            inputSchema: {
                name: z.string().optional().describe('Optional wallet name'),
                token: z.string().optional().describe('Optional ecash token (cashuA.../cashuB...) to fund the wallet immediately'),
            },
        },
        async ({ name, token }) => {
            if (!state.sessionId) await initSession(state)

            const body: Record<string, unknown> = {}
            if (name) body.name = name
            if (token) body.token = token

            const result = await apiCall(state, 'POST', '/v1/wallet', body, false)
            if (!result.ok) {
                return textResult(result.data?.error || result.data, true)
            }

            const walletAccessKey = result.data.access_key
            state.accessKey = walletAccessKey

            await prisma.mcpSession.update({
                where: { id: state.sessionId! },
                data: {
                    accessKey: walletAccessKey,
                    walletId: result.data.id || null,
                },
            })

            const { access_key: _, ...safeData } = result.data
            return textResult({
                ...safeData,
                session_id: state.sessionId,
                message: 'Wallet created and bound to this session. Access key is stored securely.',
            })
        },
    )

    server.registerTool(
        'get_rate',
        {
            description: 'Get the current Bitcoin exchange rate for a fiat currency (e.g., usd, eur)',
            inputSchema: {
                currency: z.string().describe('Fiat currency code (e.g., usd, eur, gbp)'),
            },
        },
        async ({ currency }) => {
            const result = await apiCall(state, 'GET', `/v1/rate/${currency}`, undefined, false)
            return handleApiResult(result)
        },
    )

    // --- Protected tools ---

    server.registerTool(
        'get_balance',
        {
            description: 'Get the current wallet balance and details',
        },
        async () => {
            const result = await apiCall(state, 'GET', '/v1/wallet')
            if (!result.ok) return textResult(result.data?.error || result.data, true)

            const { access_key: _, ...safeData } = result.data
            return textResult(safeData)
        },
    )

    server.registerTool(
        'deposit',
        {
            description: 'Returns a bolt11 lightning invoice that can be paid to fund the wallet.',
            inputSchema: {
                amount: z.number().min(1).describe('Amount in sats to deposit'),
            },
        },
        async ({ amount }) => {
            const result = await apiCall(state, 'POST', '/v1/wallet/deposit', { amount })
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'check_deposit',
        {
            description: 'Check the status of a deposit quote. If the Lightning invoice has been paid, wallet is funded with freshly minted ecash.',
            inputSchema: {
                quote: z.string().describe('The deposit quote ID returned by the deposit tool'),
            },
        },
        async ({ quote }) => {
            const result = await apiCall(state, 'GET', `/v1/wallet/deposit/${quote}`)
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'send',
        {
            description: 'Send ecash: creates a cashu token of the specified amount that can be sent as a payment.',
            inputSchema: {
                amount: z.number().min(1).describe('Amount to send'),
                memo: z.string().optional().describe('Optional memo to include in the token'),
            },
        },
        async ({ amount, memo }) => {
            const body: Record<string, unknown> = { amount }
            if (memo) body.memo = memo
            const result = await apiCall(state, 'POST', '/v1/wallet/send', body)
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'receive',
        {
            description: 'Receive an ecash token into the wallet. Swaps the token proofs with the mint for fresh ones.',
            inputSchema: {
                token: z.string().describe('The ecash token string (starting with cashuB... or cashuA...) to receive'),
            },
        },
        async ({ token }) => {
            const result = await apiCall(state, 'POST', '/v1/wallet/receive', { token })
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'pay',
        {
            description: 'Pay a Lightning invoice or to a lightning address. Spends ecash from the wallet to pay over the Lightning Network.',
            inputSchema: {
                amount: z.number().min(1).describe('Amount to pay'),
                bolt11_request: z.string().optional().describe('Bolt11 Lightning invoice to pay'),
                lightning_address: z.string().optional().describe('Lightning address (e.g., user@domain.com) to pay'),
            },
        },
        async ({ amount, bolt11_request, lightning_address }) => {
            const body: Record<string, unknown> = { amount }
            if (bolt11_request) body.bolt11_request = bolt11_request
            if (lightning_address) body.lightning_address = lightning_address
            const result = await apiCall(state, 'POST', '/v1/wallet/pay', body)
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'check_payment',
        {
            description: 'Check the status of an outgoing Lightning payment (melt quote)',
            inputSchema: {
                quote: z.string().describe('The payment quote ID'),
            },
        },
        async ({ quote }) => {
            const result = await apiCall(state, 'GET', `/v1/wallet/pay/${quote}`)
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'check_token',
        {
            description: 'Check the state of an ecash token\'s proofs with the mint (UNSPENT, PENDING, or SPENT)',
            inputSchema: {
                token: z.string().describe('The ecash token to check'),
            },
        },
        async ({ token }) => {
            const result = await apiCall(state, 'POST', '/v1/wallet/check', { token })
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'decode',
        {
            description: 'Decode a cashu token, bolt11 Lightning invoice, or cashu payment request to human readable format.',
            inputSchema: {
                type: z.enum(['CASHU_TOKEN_V4', 'CASHU_TOKEN_V3', 'BOLT11_REQUEST', 'CASHU_REQUEST']).describe('Type of data to decode'),
                data: z.string().describe('The encoded string to decode'),
            },
        },
        async ({ type, data }) => {
            const result = await apiCall(state, 'POST', '/v1/wallet/decode', { type, data })
            return handleApiResult(result)
        },
    )

    server.registerTool(
        'close_wallet',
        {
            description: 'Close the wallet session: sweeps the entire balance into an ecash token and returns it. The token can be used to fund a new wallet later.',
        },
        async () => {
            const balanceResult = await apiCall(state, 'GET', '/v1/wallet')
            if (!balanceResult.ok) return textResult(balanceResult.data?.error || balanceResult.data, true)

            const balance = balanceResult.data.balance
            let token: string | null = null

            if (balance > 0) {
                const sendResult = await apiCall(state, 'POST', '/v1/wallet/send', { amount: balance })
                if (!sendResult.ok) return textResult(sendResult.data?.error || sendResult.data, true)
                token = sendResult.data.token
            }

            await prisma.mcpSession.update({
                where: { id: state.sessionId! },
                data: { closedAt: new Date() },
            })

            state.accessKey = null

            return textResult({
                message: balance > 0
                    ? 'Wallet closed. Save the token below to recover your funds later.'
                    : 'Wallet closed. No balance to sweep.',
                token,
                amount: balance,
            })
        },
    )

    return { server, state }
}


// --- Transport: stdio (local, single session) ---

async function startStdio() {
    const { server, state } = createIpponMcpServer()
    await initSession(state)
    const transport = new StdioServerTransport()
    await server.connect(transport)
    log.info(`Minibits Ippon MCP server running via stdio (session: ${state.sessionId})`)
}


// --- Transport: Streamable HTTP (remote, multi-session) ---

async function startHttp() {
    const app = createMcpExpressApp({ host: '127.0.0.1' })

    // Map of session ID -> transport
    const transports: Record<string, StreamableHTTPServerTransport> = {}

    // POST /mcp — handle JSON-RPC requests
    app.post('/mcp', async (req: any, res: any) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined

        try {
            let transport: StreamableHTTPServerTransport

            if (sessionId && transports[sessionId]) {
                transport = transports[sessionId]
            } else if (!sessionId && isInitializeRequest(req.body)) {
                transport = new StreamableHTTPServerTransport({
                    sessionIdGenerator: () => randomUUID(),
                    onsessioninitialized: (sid: string) => {
                        log.info(`HTTP session initialized: ${sid}`)
                        transports[sid] = transport
                    },
                })

                transport.onclose = () => {
                    const sid = transport.sessionId
                    if (sid && transports[sid]) {
                        log.info(`HTTP session closed: ${sid}`)
                        delete transports[sid]
                    }
                }

                const { server, state } = createIpponMcpServer()
                await initSession(state)
                await server.connect(transport)
                await transport.handleRequest(req, res, req.body)
                return
            } else {
                res.status(400).json({
                    jsonrpc: '2.0',
                    error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
                    id: null,
                })
                return
            }

            await transport.handleRequest(req, res, req.body)
        } catch (error) {
            log.error('Error handling request:', error)
            if (!res.headersSent) {
                res.status(500).json({
                    jsonrpc: '2.0',
                    error: { code: -32603, message: 'Internal server error' },
                    id: null,
                })
            }
        }
    })

    // GET /mcp — SSE stream for server-to-client notifications
    app.get('/mcp', async (req: any, res: any) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined
        if (!sessionId || !transports[sessionId]) {
            res.status(400).send('Invalid or missing session ID')
            return
        }
        await transports[sessionId].handleRequest(req, res)
    })

    // DELETE /mcp — session termination
    app.delete('/mcp', async (req: any, res: any) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined
        if (!sessionId || !transports[sessionId]) {
            res.status(400).send('Invalid or missing session ID')
            return
        }
        await transports[sessionId].handleRequest(req, res)
    })

    app.listen(MCP_PORT, () => {
        log.info(`Minibits Ippon MCP server running via HTTP on port ${MCP_PORT}`)
    })

    process.on('SIGINT', async () => {
        log.info('Shutting down...')
        for (const sid in transports) {
            await transports[sid].close().catch(() => {})
            delete transports[sid]
        }
        process.exit(0)
    })
}


// --- Entry point ---

const main = TRANSPORT === 'http' ? startHttp : startStdio

main().catch((err) => {
    log.error('Fatal error:', err)
    process.exit(1)
})
