# Ethio Chereta Backend (Go)

This is the MVP backend for the Ethio Chereta tender platform, based on your SRS demo scope.

## Tech

- Go
- PostgreSQL (Neon-compatible)
- Chi router
- JWT auth

## Features implemented

- User registration and login (`admin` and `bidder`)
- Role-based authorization
- Tender creation/listing/details
- Bid submission by bidders
- Bid listing and award selection by admins
- Simple dashboard stats (`open_tenders`, `bids_received`)
- Basic local tender summarizer endpoint (placeholder for LLM integration)
- Automatic schema creation on startup
- AI summarizer via Gemini API (with local fallback)

## 1) Setup

1. Install Go 1.23+.
2. Create `.env` from `.env.example`.
3. Set real values:
   - `DATABASE_URL`
   - `JWT_SECRET`
   - `PORT` (optional)
   - `GEMINI_API_KEY` (optional, enables real AI summarizer)
   - `GEMINI_MODEL` (optional, default `gemini-1.5-flash`)

## 2) Install dependencies

```bash
go mod tidy
```

## 3) Run

```bash
go run ./cmd/api
```

Server starts on `http://localhost:8080` by default.

## API overview

- `GET /healthz`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/tenders` (auth)
- `GET /api/v1/tenders/{id}` (auth)
- `POST /api/v1/tenders` (admin)
- `POST /api/v1/tenders/{id}/bids` (bidder)
- `GET /api/v1/tenders/{id}/bids` (admin)
- `POST /api/v1/tenders/{id}/award` (admin)
- `GET /api/v1/dashboard` (admin)
- `POST /api/v1/ai/summarize` (auth)

If `GEMINI_API_KEY` is set, `/api/v1/ai/summarize` uses Gemini.
If not set (or if Gemini fails), it automatically falls back to a local summarizer.

## Example request payloads

Register:

```json
{
  "full_name": "Abebe Kebede",
  "email": "abebe@example.com",
  "password": "securepass123",
  "role": "bidder"
}
```

Create tender (admin):

```json
{
  "title": "Road Construction in Addis Ababa",
  "description": "Construction and asphalt work...",
  "deadline": "2026-04-30T23:59:59Z",
  "estimated_budget": 1500000
}
```

Submit bid (bidder):

```json
{
  "price": 1400000,
  "comment": "We can deliver in 90 days",
  "attachment_url": "https://example.com/proposal.pdf"
}
```

## Notes

- This is a demo-level security implementation (JWT + hashed passwords).
- For production: add stronger validation, rate limiting, HTTPS, secret management, audit trails, and proper file upload storage.
