package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	db        *pgxpool.Pool
	jwtSecret []byte
	httpClient *http.Client
	geminiKey  string
	geminiModel string
}

type UserClaims struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("note: no .env loaded (%v) — using process environment only", err)
	}

	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	db, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("db connection failed: %v", err)
	}
	defer db.Close()

	if err := runMigrations(ctx, db); err != nil {
		log.Fatalf("migrations failed: %v", err)
	}

	geminiModel := os.Getenv("GEMINI_MODEL")
	if geminiModel == "" {
		geminiModel = "gemini-1.5-flash"
	}

	app := &App{
		db:         db,
		jwtSecret:  []byte(jwtSecret),
		httpClient: &http.Client{Timeout: 20 * time.Second},
		geminiKey:  strings.TrimSpace(os.Getenv("GEMINI_API_KEY")),
		geminiModel: geminiModel,
	}
	r := chi.NewRouter()
	r.Use(chimw.RequestID, chimw.RealIP, chimw.Logger, chimw.Recoverer, chimw.Timeout(60*time.Second))

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/register", app.register)
		r.Post("/auth/login", app.login)
		r.Group(func(r chi.Router) {
			r.Use(app.authMiddleware)
			r.Get("/tenders", app.listTenders)
			r.Get("/tenders/{id}", app.getTender)
			r.With(app.requireRole("bidder")).Post("/tenders/{id}/bids", app.submitBid)
			r.With(app.requireRole("admin")).Get("/tenders/{id}/bids", app.listTenderBids)
			r.With(app.requireRole("admin")).Post("/tenders", app.createTender)
			r.With(app.requireRole("admin")).Post("/tenders/{id}/award", app.awardBid)
			r.With(app.requireRole("admin")).Get("/dashboard", app.dashboard)
			r.Post("/ai/summarize", app.summarizeTender)
		})
	})

	log.Printf("server listening on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}

func runMigrations(ctx context.Context, db *pgxpool.Pool) error {
	schema := `
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'bidder')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenders (
  id BIGSERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  deadline TIMESTAMPTZ NOT NULL,
  estimated_budget NUMERIC(14,2) NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'awarded')),
  created_by BIGINT NOT NULL REFERENCES users(id),
  winning_bid_id BIGINT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS bids (
  id BIGSERIAL PRIMARY KEY,
  tender_id BIGINT NOT NULL REFERENCES tenders(id) ON DELETE CASCADE,
  bidder_id BIGINT NOT NULL REFERENCES users(id),
  price NUMERIC(14,2) NOT NULL,
  comment TEXT,
  attachment_url TEXT,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tender_id, bidder_id)
);

ALTER TABLE tenders
  DROP CONSTRAINT IF EXISTS tenders_winning_bid_id_fkey;

ALTER TABLE tenders
  ADD CONSTRAINT tenders_winning_bid_id_fkey
  FOREIGN KEY (winning_bid_id) REFERENCES bids(id) ON DELETE SET NULL;
`
	_, err := db.Exec(ctx, schema)
	return err
}

type registerReq struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (a *App) register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Role = strings.TrimSpace(strings.ToLower(req.Role))
	if req.FullName == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "full_name, email and password are required")
		return
	}
	if req.Role != "admin" && req.Role != "bidder" {
		writeError(w, http.StatusBadRequest, "role must be admin or bidder")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	pw, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	var userID int64
	err = a.db.QueryRow(r.Context(), `
INSERT INTO users (full_name, email, password_hash, role)
VALUES ($1, $2, $3, $4)
RETURNING id`, req.FullName, req.Email, string(pw), req.Role).Scan(&userID)
	if err != nil {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"user_id": userID,
		"message": "registration successful",
	})
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	var userID int64
	var role, pwHash string
	err := a.db.QueryRow(r.Context(), `SELECT id, role, password_hash FROM users WHERE email = $1`, req.Email).
		Scan(&userID, &role, &pwHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := a.createJWT(userID, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"role":  role,
	})
}

type createTenderReq struct {
	Title           string  `json:"title"`
	Description     string  `json:"description"`
	Deadline        string  `json:"deadline"`
	EstimatedBudget float64 `json:"estimated_budget"`
}

func (a *App) createTender(w http.ResponseWriter, r *http.Request) {
	var req createTenderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Title == "" || req.Description == "" || req.Deadline == "" || req.EstimatedBudget <= 0 {
		writeError(w, http.StatusBadRequest, "title, description, deadline and estimated_budget are required")
		return
	}
	deadline, err := time.Parse(time.RFC3339, req.Deadline)
	if err != nil {
		writeError(w, http.StatusBadRequest, "deadline must be RFC3339 format")
		return
	}
	claims := claimsFromContext(r.Context())
	var tenderID int64
	err = a.db.QueryRow(r.Context(), `
INSERT INTO tenders (title, description, deadline, estimated_budget, created_by)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`, req.Title, req.Description, deadline, req.EstimatedBudget, claims.UserID).Scan(&tenderID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create tender")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tender_id": tenderID})
}

func (a *App) listTenders(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.Query(r.Context(), `
SELECT id, title, description, deadline, estimated_budget, status, created_at
FROM tenders ORDER BY created_at DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list tenders")
		return
	}
	defer rows.Close()

	type tender struct {
		ID              int64     `json:"id"`
		Title           string    `json:"title"`
		Description     string    `json:"description"`
		Deadline        time.Time `json:"deadline"`
		EstimatedBudget float64   `json:"estimated_budget"`
		Status          string    `json:"status"`
		CreatedAt       time.Time `json:"created_at"`
	}
	var tenders []tender
	for rows.Next() {
		var t tender
		if err := rows.Scan(&t.ID, &t.Title, &t.Description, &t.Deadline, &t.EstimatedBudget, &t.Status, &t.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to parse tenders")
			return
		}
		tenders = append(tenders, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tenders})
}

func (a *App) getTender(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tender id")
		return
	}
	var item struct {
		ID              int64     `json:"id"`
		Title           string    `json:"title"`
		Description     string    `json:"description"`
		Deadline        time.Time `json:"deadline"`
		EstimatedBudget float64   `json:"estimated_budget"`
		Status          string    `json:"status"`
		CreatedAt       time.Time `json:"created_at"`
	}
	err = a.db.QueryRow(r.Context(), `
SELECT id, title, description, deadline, estimated_budget, status, created_at
FROM tenders WHERE id = $1`, id).Scan(
		&item.ID, &item.Title, &item.Description, &item.Deadline, &item.EstimatedBudget, &item.Status, &item.CreatedAt,
	)
	if err != nil {
		writeError(w, http.StatusNotFound, "tender not found")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type submitBidReq struct {
	Price         float64 `json:"price"`
	Comment       string  `json:"comment"`
	AttachmentURL string  `json:"attachment_url"`
}

func (a *App) submitBid(w http.ResponseWriter, r *http.Request) {
	tenderID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tender id")
		return
	}

	var req submitBidReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Price <= 0 {
		writeError(w, http.StatusBadRequest, "price must be greater than zero")
		return
	}

	var status string
	var deadline time.Time
	err = a.db.QueryRow(r.Context(), `SELECT status, deadline FROM tenders WHERE id = $1`, tenderID).Scan(&status, &deadline)
	if err != nil {
		writeError(w, http.StatusNotFound, "tender not found")
		return
	}
	if status != "open" || time.Now().After(deadline) {
		writeError(w, http.StatusBadRequest, "tender is closed for submissions")
		return
	}

	claims := claimsFromContext(r.Context())
	var bidID int64
	err = a.db.QueryRow(r.Context(), `
INSERT INTO bids (tender_id, bidder_id, price, comment, attachment_url)
VALUES ($1, $2, $3, $4, $5)
RETURNING id`, tenderID, claims.UserID, req.Price, req.Comment, req.AttachmentURL).Scan(&bidID)
	if err != nil {
		writeError(w, http.StatusConflict, "you already submitted a bid for this tender")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"bid_id":      bidID,
		"submitted_at": time.Now().UTC(),
	})
}

func (a *App) listTenderBids(w http.ResponseWriter, r *http.Request) {
	tenderID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tender id")
		return
	}
	rows, err := a.db.Query(r.Context(), `
SELECT b.id, b.tender_id, b.bidder_id, u.full_name, b.price, b.comment, b.attachment_url, b.submitted_at
FROM bids b
JOIN users u ON u.id = b.bidder_id
WHERE b.tender_id = $1
ORDER BY b.submitted_at DESC`, tenderID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load bids")
		return
	}
	defer rows.Close()

	type bid struct {
		ID            int64     `json:"id"`
		TenderID      int64     `json:"tender_id"`
		BidderID      int64     `json:"bidder_id"`
		BidderName    string    `json:"bidder_name"`
		Price         float64   `json:"price"`
		Comment       string    `json:"comment"`
		AttachmentURL string    `json:"attachment_url"`
		SubmittedAt   time.Time `json:"submitted_at"`
	}
	var bids []bid
	for rows.Next() {
		var b bid
		if err := rows.Scan(&b.ID, &b.TenderID, &b.BidderID, &b.BidderName, &b.Price, &b.Comment, &b.AttachmentURL, &b.SubmittedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to parse bids")
			return
		}
		bids = append(bids, b)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": bids})
}

type awardReq struct {
	BidID int64 `json:"bid_id"`
}

func (a *App) awardBid(w http.ResponseWriter, r *http.Request) {
	tenderID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid tender id")
		return
	}
	var req awardReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.BidID <= 0 {
		writeError(w, http.StatusBadRequest, "bid_id is required")
		return
	}

	ct, err := a.db.Exec(r.Context(), `
UPDATE tenders
SET status = 'awarded', winning_bid_id = $1
WHERE id = $2 AND EXISTS (
  SELECT 1 FROM bids WHERE id = $1 AND tender_id = $2
)`, req.BidID, tenderID)
	if err != nil || ct.RowsAffected() == 0 {
		writeError(w, http.StatusBadRequest, "unable to award selected bid")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "winner selected"})
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	var openTenders, totalBids int64
	if err := a.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM tenders WHERE status = 'open'`).Scan(&openTenders); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load dashboard")
		return
	}
	if err := a.db.QueryRow(r.Context(), `SELECT COUNT(*) FROM bids`).Scan(&totalBids); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load dashboard")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{
		"open_tenders": openTenders,
		"bids_received": totalBids,
	})
}

type summarizeReq struct {
	Description string `json:"description"`
}

func (a *App) summarizeTender(w http.ResponseWriter, r *http.Request) {
	var req summarizeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	text := strings.TrimSpace(req.Description)
	if text == "" {
		writeError(w, http.StatusBadRequest, "description is required")
		return
	}

	if a.geminiKey != "" {
		points, err := a.summarizeWithGemini(r.Context(), text)
		if err == nil && len(points) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{
				"summary_points": points,
				"source":         "gemini",
			})
			return
		}
	}

	points := summarizeToBullets(text)
	writeJSON(w, http.StatusOK, map[string]any{
		"summary_points": points,
		"source":         "local_fallback",
	})
}

func (a *App) summarizeWithGemini(ctx context.Context, text string) ([]string, error) {
	prompt := "Summarize this tender description in 3 to 5 short bullet points. Return only bullet lines.\n\n" + text
	body := map[string]any{
		"contents": []map[string]any{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
		"generationConfig": map[string]any{
			"temperature":     0.2,
			"maxOutputTokens": 300,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", a.geminiModel, a.geminiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gemini request failed: status %d", resp.StatusCode)
	}

	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return nil, errors.New("empty gemini response")
	}

	resultText := strings.TrimSpace(parsed.Candidates[0].Content.Parts[0].Text)
	if resultText == "" {
		return nil, errors.New("empty summary text")
	}

	lines := strings.Split(resultText, "\n")
	var points []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.TrimLeft(line, "-*• ")
		if line == "" {
			continue
		}
		points = append(points, line)
		if len(points) == 5 {
			break
		}
	}
	if len(points) == 0 {
		return summarizeToBullets(resultText), nil
	}
	return points, nil
}

func summarizeToBullets(text string) []string {
	sentences := strings.FieldsFunc(text, func(r rune) bool {
		return r == '.' || r == '!' || r == '?'
	})
	var out []string
	for _, s := range sentences {
		clean := strings.TrimSpace(s)
		if clean == "" {
			continue
		}
		out = append(out, clean)
		if len(out) == 4 {
			break
		}
	}
	if len(out) == 0 {
		return []string{text}
	}
	return out
}

func (a *App) createJWT(userID int64, role string) (string, error) {
	claims := UserClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(a.jwtSecret)
}

type ctxKey string

const claimsCtxKey ctxKey = "claims"

func (a *App) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("invalid signing method")
			}
			return a.jwtSecret, nil
		})
		if err != nil || !token.Valid {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		claims, ok := token.Claims.(*UserClaims)
		if !ok {
			writeError(w, http.StatusUnauthorized, "invalid token claims")
			return
		}
		ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := claimsFromContext(r.Context())
			if claims.Role != role {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func claimsFromContext(ctx context.Context) *UserClaims {
	claims, _ := ctx.Value(claimsCtxKey).(*UserClaims)
	return claims
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
