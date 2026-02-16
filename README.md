# Minibits Ippon MCP Server

A companion [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server for [Minibits Ippon](../minibits_ippon) — a minimalistic, API-driven ecash and Lightning wallet for AI agents implementing the Cashu protocol.

This server wraps the Ippon wallet REST API, giving AI agents MCP tool access to create wallets, send and receive ecash tokens, pay Lightning invoices, and more. It manages session lifecycle and safeguards wallet access keys so that agents never handle them directly.

## Prerequisites

- Node.js 24+
- PostgreSQL database
- Running instance of [Minibits Ippon](https://github.com/minibits-cash/minibits_ippon) wallet API

## Setup

1. Install dependencies:

```bash
yarn install
```

2. Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | — |
| `IPPON_URL` | Ippon wallet API base URL | `http://localhost:3001` |
| `MCP_TRANSPORT` | Transport mode: `stdio` or `http` | `stdio` |
| `MCP_PORT` | HTTP server port (when using `http` transport) | `3002` |

3. Push the database schema:

```bash
npx prisma db push
```

## Build & Run

```bash
# Build
yarn build

# Run (stdio transport, for local MCP clients)
yarn start:stdio

# Run (HTTP transport, for remote MCP clients)
yarn start:http
```

For development with auto-reload:

```bash
yarn start:dev
```

## Available Tools

| Tool | Description |
|---|---|
| `get_info` | Get Ippon service info, mint URL, and limits |
| `get_rate` | Get Bitcoin exchange rate for a fiat currency |
| `create_wallet` | Create a new ecash wallet bound to the session |
| `get_balance` | Get wallet balance and details |
| `deposit` | Get a Lightning invoice to fund the wallet |
| `check_deposit` | Check status of a deposit |
| `send` | Create a cashu token to send as payment |
| `receive` | Receive an ecash token into the wallet |
| `pay` | Pay a Lightning invoice or lightning address |
| `check_payment` | Check status of an outgoing payment |
| `check_token` | Check state of ecash token proofs |
| `decode` | Decode cashu tokens, Lightning invoices, or cashu payment requests |
| `close_wallet` | Sweep balance into a token and close the session |

## License

MIT
