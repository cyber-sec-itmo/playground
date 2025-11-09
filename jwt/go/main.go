package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// --- DATA STRUCTURE ---

// Token represents a JWT token
type Token struct {
	Id        string    `json:"id"` // jti (UUID)
	IsRevoked bool      `json:"is_revoked"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Optional audit fields:
	Token      string     `json:"token,omitempty"` // jwt full token string
	ClientIP   string     `json:"client_ip,omitempty"`
	UserAgent  string     `json:"user_agent,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// --- DATABASE ---

// SqliteDB represents a SQLite database connection
type SqliteDB struct {
	db *sql.DB
}

// NewSqliteDB creates a new SQLite database connection with specified options
func NewSqliteDB(uri string, enableWal bool, syncPragma string) (*SqliteDB, error) {
	params := url.Values{}
	params.Add("_synchronous", "NORMAL")
	params.Add("_journal_mode", "WAL")

	constructedUri := uri
	if len(params) > 0 {
		if strings.Contains(uri, "?") {
			constructedUri += "&" + params.Encode()
		} else {
			constructedUri += "?" + params.Encode()
		}
	}

	db, err := sql.Open("sqlite3", constructedUri)
	if err != nil {
		return nil, fmt.Errorf("failed to open database with DSN '%s': %w", constructedUri, err)
	}

	// Configure connection pool settings
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Enable foreign key support for this connection.
	// This is crucial for ON DELETE CASCADE and other FK actions to work.
	_, err = db.Exec("PRAGMA foreign_keys = ON;")
	if err != nil {
		db.Close() // Close DB if we can't set the pragma
		return nil, fmt.Errorf("failed to enable foreign key support for DSN '%s': %w", constructedUri, err)
	}

	return &SqliteDB{db: db}, nil
}

// RunMigrations applies migrations to the database
func (s *SqliteDB) RunMigrations(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	m1 := `CREATE TABLE IF NOT EXISTS tokens (
		id          TEXT PRIMARY KEY,
		is_revoked  INTEGER NOT NULL,
		issued_at   TEXT NOT NULL,
		expires_at  TEXT NOT NULL,
		updated_at  TEXT NOT NULL
	)`

	// Run migrations
	if _, err := s.db.ExecContext(ctx, m1); err != nil {
		return fmt.Errorf("failed to run migration m1: %w", err)
	}

	return nil
}

// TestConnection tests the database connection with a timeout
func (s *SqliteDB) TestConnection(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return s.db.PingContext(ctx)
}

// Close closes the database connection
func (s *SqliteDB) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *SqliteDB) ListTokens(ctx context.Context) ([]Token, error) {
	query := "SELECT id, is_revoked, issued_at, expires_at, updated_at FROM tokens ORDER BY updated_at"

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tokens: %w", err)
	}
	defer rows.Close()

	tokens := []Token{}
	for rows.Next() {
		var token Token
		var issuedAtStr, expiresAtStr, updatedAtStr string
		var isRevokedInt int

		err := rows.Scan(&token.Id, &isRevokedInt, &issuedAtStr, &expiresAtStr, &updatedAtStr)
		if err != nil {
			return nil, fmt.Errorf("failed to scan token row: %w", err)
		}

		// Convert INTEGER to boolean
		token.IsRevoked = isRevokedInt != 0

		// Parse Unix timestamps to time.Time
		issuedAtUnix, err := strconv.ParseInt(issuedAtStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issued_at: %w", err)
		}
		token.IssuedAt = time.Unix(issuedAtUnix, 0)

		expiresAtUnix, err := strconv.ParseInt(expiresAtStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse expires_at: %w", err)
		}
		token.ExpiresAt = time.Unix(expiresAtUnix, 0)

		updatedAtUnix, err := strconv.ParseInt(updatedAtStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse updated_at: %w", err)
		}
		token.UpdatedAt = time.Unix(updatedAtUnix, 0)

		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating token rows: %w", err)
	}

	return tokens, nil
}

// CreateToken creates a new token record in the database
func (s *SqliteDB) CreateToken(ctx context.Context, token Token) error {
	query := `
	INSERT INTO tokens (
	    id, is_revoked, issued_at, expires_at, updated_at
	) VALUES (?, ?, ?, ?, ?);
	`

	isRevokedInt := 0
	if token.IsRevoked {
		isRevokedInt = 1
	}

	_, err := s.db.ExecContext(
		ctx,
		query,
		token.Id,
		isRevokedInt,
		token.IssuedAt.Unix(),
		token.ExpiresAt.Unix(),
		token.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("CreateToken: failed to insert: %w", err)
	}
	return nil
}

// --- SERVER ---

// Server holds server state and dependencies
type Server struct {
	SDB       SqliteDB
	JWTSecret []byte
}

// Handle panic errors to prevent server shutdown
func (s *Server) panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				fmt.Printf("panicMiddleware, error: %v", err)
				http.Error(w, "Internal server error", 500)
			}
		}()
		// There will be a defer with panic handler in each next function
		next.ServeHTTP(w, r)
	})
}

// Log access requests in proper format
func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		next.ServeHTTP(w, r)

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, fmt.Sprintf("Unable to parse client IP: %s", r.RemoteAddr), http.StatusBadRequest)
			return
		}
		log.Printf("%s %s %s\n", ip, r.Method, r.URL.Path)
	})
}

// Ping handles the ping-pong endpoint
func (s *Server) Ping(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

// Tokens returns list of tokens from database
func (s *Server) Tokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokens, err := s.SDB.ListTokens(r.Context())
	if err != nil {
		log.Printf("Tokens, error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(tokens); err != nil {
		log.Printf("Tokens, error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// SignUp creates a new JWT token and stores it in the database
func (s *Server) SignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse the form", http.StatusBadGateway)
		return
	}

	expSecStr := r.FormValue("expires_sec")
	expDuration := 24 * time.Hour // default 24 hours
	if expSecStr != "" {
		if expSec, err := strconv.ParseInt(expSecStr, 10, 64); err == nil {
			expDuration = time.Duration(expSec) * time.Second
		} else {
			http.Error(w, "Invalid expires_sec parameter", http.StatusBadRequest)
			return
		}
	}

	// Setup token
	now := time.Now()
	expiresAt := now.Add(expDuration)
	tokenId := uuid.New()

	// Create JWT claims
	claims := jwt.MapClaims{
		"jti": tokenId,          // JWT ID
		"iat": now.Unix(),       // Issued at
		"exp": expiresAt.Unix(), // Expiration time
		"nbf": now.Unix(),       // Not before
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token with secret
	tokenString, err := token.SignedString(s.JWTSecret)
	if err != nil {
		log.Printf("SignUp, error signing token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Collect client info for replay analysis
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	t := Token{
		Id:        tokenId.String(),
		IsRevoked: false,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		UpdatedAt: now,

		Token:     tokenString,
		ClientIP:  clientIP,
		UserAgent: r.UserAgent(),
	}

	// Store token in database
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.SDB.CreateToken(ctx, t); err != nil {
		log.Printf("SignUp, error storing token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(t); err != nil {
		log.Printf("SignUp, error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// --- MAIN ENTRYPOINT ---

const (
	DefaultDatabaseSqliteURI = "jwtgo.sqlite"

	DefaultServerAddr = "localhost"
	DefaultServerPort = "8080"

	DefaultJWTSecret = "00000000-0000-0000-1000-000000000000"
)

func main() {
	dbUri := os.Getenv("DATABASE_URI")
	if dbUri == "" {
		dbUri = DefaultDatabaseSqliteURI
	}

	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = DefaultServerAddr
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = DefaultServerPort
	} else {
		if _, err := strconv.Atoi(serverPort); err != nil {
			fmt.Printf("Invalid port: %s, must be a number", serverPort)
			os.Exit(1)
		}
	}

	// Initialize database connection using registry
	fmt.Println("Initializing database connection")
	database, err := NewSqliteDB(dbUri, true, "NORMAL")
	if err != nil {
		fmt.Printf("Failed to initialize database connection, error: %v", err)
		os.Exit(1)
	}

	// Test database connection
	if err := database.TestConnection(context.Background()); err != nil {
		fmt.Printf("Failed to test database connection, error: %v", err)
		os.Exit(1)
	}
	fmt.Println("Database connection established successfully")

	if err := database.RunMigrations(context.Background()); err != nil {
		fmt.Printf("Failed to run database migrations, error: %v", err)
		os.Exit(1)
	}
	fmt.Println("Database migrations applied")

	// Create context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Get JWT secret from environment or use default
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		fmt.Println("Set default JWT secret")
		jwtSecret = DefaultJWTSecret
	}

	// Create HTTP server
	server := Server{
		SDB:       *database,
		JWTSecret: []byte(jwtSecret),
	}

	mux := http.NewServeMux()

	// Register routes
	mux.HandleFunc("/ping", server.Ping)
	mux.HandleFunc("/tokens", server.Tokens)
	mux.HandleFunc("/signup", server.SignUp)

	commonHandler := server.logMiddleware(mux)
	commonHandler = server.panicMiddleware(commonHandler)

	s := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", serverAddr, serverPort),
		Handler: commonHandler,
	}

	// Start server in a goroutine
	go func() {
		fmt.Printf("Starting HTTP server at %s:%s\n", serverAddr, serverPort)
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Server error, error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	fmt.Println("Received shutdown signal, starting graceful shutdown")

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully close database connection
	fmt.Println("Closing database connection")
	database.Close()

	// Attempt graceful shutdown of HTTP server
	if err := s.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Server shutdown error, error: %v", err)
	} else {
		fmt.Println("Server shutdown completed successfully")
	}

	fmt.Println("Application shutdown complete")
}
